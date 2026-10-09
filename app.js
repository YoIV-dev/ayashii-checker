(function () {
  'use strict';

  const { Scanner, SAMPLES, JSZip } = window;
  const $ = (sel) => document.querySelector(sel);

  const MAX_TEXT_BYTES = 3 * 1024 * 1024;
  const MAX_FILES = 8000;
  const SKIP_DIRS = /(^|\/)(\.git|node_modules|\.venv|venv|__pycache__|\.next|\.nuxt|\.cache|vendor\/bundle|Pods|\.gradle|target\/debug|target\/release)(\/|$)/;
  const SKIP_EXT = /\.(png|jpe?g|gif|webp|ico|icns|bmp|tiff?|mp[34]|mov|avi|wav|ogg|flac|woff2?|ttf|otf|eot|pdf|psd|sketch|fig|pyc|class|o|a|lib|jar|db|sqlite)$/i;
  const SEV_ORDER = ['critical', 'high', 'medium', 'low'];

  // ---------------------------------------------------------------- tabs
  const tabs = [...document.querySelectorAll('[role=tab]')];
  tabs.forEach((tab) => {
    tab.addEventListener('click', () => selectTab(tab));
    tab.addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      const next = tabs[(tabs.indexOf(tab) + (e.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length];
      selectTab(next);
      next.focus();
    });
  });
  function selectTab(tab) {
    tabs.forEach((t) => {
      const on = t === tab;
      t.setAttribute('aria-selected', on);
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute('aria-controls')).hidden = !on;
    });
  }

  // ---------------------------------------------------------------- text input
  $('#scan-text').addEventListener('click', () => {
    const text = $('#text-input').value;
    if (!text.trim()) { $('#text-input').focus(); return; }
    const findings = Scanner.scanText('貼り付けたテキスト', text);
    render([{ path: '貼り付けたテキスト', findings }], { scanned: 1, skipped: 0 });
  });
  $('#sample').addEventListener('change', (e) => {
    const s = SAMPLES[e.target.value];
    if (!s) return;
    $('#text-input').value = s;
    $('#scan-text').click();
  });

  // 入力と結果はメモリ上だけに置き、ページを離れるときに消す。
  // autocomplete="off" に加えて、ブラウザのフォーム復元や戻る/進むキャッシュにも残さない。
  function clearAll() {
    $('#text-input').value = '';
    $('#sample').value = '';
    $('#results').hidden = true;
    $('#verdict').innerHTML = '';
    $('#filters').innerHTML = '';
    $('#file-list').innerHTML = '';
    state = { results: [], filter: 'all' };
  }
  $('#clear').addEventListener('click', () => { clearAll(); $('#text-input').focus(); });
  window.addEventListener('pagehide', clearAll);
  window.addEventListener('pageshow', (e) => { if (e.persisted) clearAll(); });

  // ---------------------------------------------------------------- file input
  const drop = $('#drop');
  ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, () => drop.classList.remove('over')));
  drop.addEventListener('drop', async (e) => {
    e.preventDefault();
    const items = [...(e.dataTransfer.items || [])];
    const entries = items.map((it) => it.webkitGetAsEntry && it.webkitGetAsEntry()).filter(Boolean);
    if (entries.length) {
      const files = [];
      showProgress(0, 'ファイルを集めています…');
      for (const entry of entries) await collectEntry(entry, '', files);
      scanFiles(files);
    } else {
      scanFiles([...e.dataTransfer.files].map((f) => ({ path: f.name, file: f })));
    }
  });
  drop.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('#pick-files').click(); }
  });
  $('#pick-files').addEventListener('change', (e) => {
    scanFiles([...e.target.files].map((f) => ({ path: f.name, file: f })));
    e.target.value = '';
  });
  $('#pick-folder').addEventListener('change', (e) => {
    scanFiles([...e.target.files].map((f) => ({ path: f.webkitRelativePath || f.name, file: f })));
    e.target.value = '';
  });

  function collectEntry(entry, prefix, out) {
    return new Promise((resolve) => {
      const path = prefix + entry.name;
      if (entry.isFile) {
        entry.file((f) => { out.push({ path, file: f }); resolve(); }, () => resolve());
      } else if (entry.isDirectory) {
        if (!includeDeps() && SKIP_DIRS.test(path + '/')) { out.push({ path: path + '/', skippedDir: true }); resolve(); return; }
        const reader = entry.createReader();
        const all = [];
        const readBatch = () => reader.readEntries(async (batch) => {
          if (!batch.length) {
            for (const child of all) {
              if (out.length > MAX_FILES) break;
              await collectEntry(child, path + '/', out);
            }
            resolve();
          } else { all.push(...batch); readBatch(); }
        }, () => resolve());
        readBatch();
      } else resolve();
    });
  }

  const includeDeps = () => $('#opt-node-modules').checked;

  // ---------------------------------------------------------------- scanning
  async function scanFiles(list) {
    if (!list.length) return;
    const results = [];
    const stats = { scanned: 0, skipped: 0, skippedDirs: new Set(), tooLarge: 0, zips: 0 };
    const queue = [];

    for (const item of list) {
      if (item.skippedDir) { stats.skippedDirs.add(item.path.split('/').filter(Boolean).pop()); continue; }
      if (/\.zip$/i.test(item.path) && JSZip) {
        try {
          showProgress(0, `${item.path} を展開しています…`);
          const zip = await JSZip.loadAsync(item.file);
          stats.zips++;
          zip.forEach((rel, zf) => {
            if (zf.dir) return;
            queue.push({ path: `${item.path}/${rel}`, zipFile: zf, size: zf._data && zf._data.uncompressedSize });
          });
        } catch (err) {
          results.push({ path: item.path, findings: [], error: 'ZIPを開けませんでした（破損またはパスワード付き）' });
        }
        continue;
      }
      queue.push({ path: item.path, file: item.file, size: item.file.size });
    }

    let done = 0;
    for (const item of queue.slice(0, MAX_FILES)) {
      done++;
      if (done % 25 === 0) { showProgress(done / queue.length, `${done} / ${queue.length} ファイル`); await tick(); }
      const p = item.path;
      if (!includeDeps() && SKIP_DIRS.test(p)) {
        const m = p.match(SKIP_DIRS);
        stats.skippedDirs.add(m[2]);
        stats.skipped++;
        continue;
      }
      if (SKIP_EXT.test(p)) { stats.skipped++; continue; }
      try {
        const bytes = item.zipFile
          ? await item.zipFile.async('uint8array')
          : new Uint8Array(await item.file.arrayBuffer());
        if (Scanner.isProbablyBinary(bytes)) {
          const f = Scanner.scanBinary(p, bytes);
          if (f.length) results.push({ path: p, findings: f });
          stats.skipped += f.length ? 0 : 1;
          if (f.length) stats.scanned++;
          continue;
        }
        if (bytes.length > MAX_TEXT_BYTES) { stats.tooLarge++; stats.skipped++; continue; }
        const text = new TextDecoder('utf-8').decode(bytes);
        stats.scanned++;
        const findings = Scanner.scanText(p, text);
        if (findings.length) results.push({ path: p, findings });
      } catch (err) {
        results.push({ path: p, findings: [], error: '読み込めませんでした' });
      }
    }
    if (queue.length > MAX_FILES) stats.truncated = queue.length - MAX_FILES;
    hideProgress();
    render(results, stats);
  }

  const tick = () => new Promise((r) => setTimeout(r, 0));

  function showProgress(ratio, msg) {
    const el = $('#progress');
    el.hidden = false;
    el.querySelector('span').style.width = Math.round(ratio * 100) + '%';
    el.querySelector('p').textContent = msg;
  }
  function hideProgress() { $('#progress').hidden = true; }

  // ---------------------------------------------------------------- render
  let state = { results: [], filter: 'all' };

  const VERDICT = {
    danger: { title: '危険', icon: '!', text: '悪意のあるコードや隠された命令の可能性が高いパターンが見つかりました。実行したり、AIに読ませたりしないでください。' },
    warn: { title: '要注意', icon: '?', text: '注意が必要な箇所があります。それぞれの理由を読み、作者や配布元が信頼できるか確認してから使ってください。' },
    info: { title: '軽微な注意点のみ', icon: 'i', text: '大きな問題は見つかりませんでしたが、念のため確認したほうがよい箇所があります。' },
    safe: { title: '問題は見つかりませんでした', icon: '✓', text: '既知の危険パターンは検出されませんでした。ただし安全の保証ではありません。' },
  };

  function render(results, stats) {
    const all = results.flatMap((r) => r.findings);
    const sum = Scanner.summarize(all);
    state = { results, filter: 'all', sum, stats };

    const v = VERDICT[sum.level];
    const notes = [];
    notes.push(`${stats.scanned.toLocaleString()} ファイルを解析`);
    if (stats.zips) notes.push(`ZIP ${stats.zips} 個を展開`);
    if (stats.skipped) notes.push(`画像・依存フォルダなど ${stats.skipped.toLocaleString()} 件をスキップ`);
    if (stats.tooLarge) notes.push(`3MB超のファイル ${stats.tooLarge} 件は未解析`);
    if (stats.truncated) notes.push(`上限を超えた ${stats.truncated} 件は未解析`);
    const skippedDirs = stats.skippedDirs && stats.skippedDirs.size ? [...stats.skippedDirs] : [];

    const verdict = $('#verdict');
    verdict.className = `verdict level-${sum.level}`;
    verdict.innerHTML = `
      <div class="verdict-head">
        <span class="verdict-icon" aria-hidden="true">${v.icon}</span>
        <div>
          <p class="verdict-label">判定結果</p>
          <h2>${v.title}</h2>
        </div>
        <div class="verdict-score"><span>${sum.score}</span><small>危険度スコア</small></div>
      </div>
      <p class="verdict-text">${v.text}</p>
      <ul class="sev-counts">
        ${SEV_ORDER.map((s) => `<li class="sev-${s}"><b>${sum.bySev[s]}</b> ${Scanner.SEV[s].label}</li>`).join('')}
      </ul>
      <p class="scan-notes">${notes.map(esc).join(' ・ ')}${skippedDirs.length ? `<br>${esc(skippedDirs.join(', '))} は除外しました（上のチェックで含められます）` : ''}</p>`;

    renderFilters();
    renderList();
    $('#results').hidden = false;
    $('#results').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function renderFilters() {
    const cats = Object.entries(state.sum.byCat).sort((a, b) => b[1] - a[1]);
    const el = $('#filters');
    if (!cats.length) { el.innerHTML = ''; return; }
    el.innerHTML = [['all', 'すべて', state.sum.total], ...cats.map(([c, n]) => [c, Scanner.CAT[c] || c, n])]
      .map(([key, label, n]) => `<button class="chip" data-cat="${key}" aria-pressed="${state.filter === key}">${esc(label)} <span>${n}</span></button>`)
      .join('');
    el.querySelectorAll('.chip').forEach((b) => b.addEventListener('click', () => {
      state.filter = b.dataset.cat;
      renderFilters();
      renderList();
    }));
  }

  function renderList() {
    const el = $('#file-list');
    const rank = (f) => Scanner.SEV[f.sev].rank;
    const files = state.results
      .map((r) => ({ ...r, findings: r.findings.filter((f) => state.filter === 'all' || f.cat === state.filter) }))
      .filter((r) => r.findings.length || (r.error && state.filter === 'all'))
      .map((r) => ({ ...r, max: Math.max(0, ...r.findings.map(rank)) }))
      .sort((a, b) => b.max - a.max || b.findings.length - a.findings.length || a.path.localeCompare(b.path));

    if (!files.length) {
      el.innerHTML = state.sum.total ? '' : '<p class="empty">検出された項目はありません。</p>';
      return;
    }

    el.innerHTML = files.map((r, idx) => {
      const sorted = r.findings.slice().sort((a, b) => rank(b) - rank(a) || a.line - b.line);
      const top = sorted[0] ? sorted[0].sev : 'low';
      return `
      <details class="file" ${idx < 8 && r.max >= 3 ? 'open' : ''}>
        <summary>
          <span class="badge sev-${r.error ? 'low' : top}">${r.error ? 'エラー' : Scanner.SEV[top].label}</span>
          <span class="path">${esc(r.path)}</span>
          <span class="count">${r.error ? esc(r.error) : r.findings.length + '件'}</span>
        </summary>
        <ol class="findings">${sorted.map(renderFinding).join('')}</ol>
      </details>`;
    }).join('');
  }

  function renderFinding(f) {
    return `
      <li class="finding">
        <div class="f-head">
          <span class="badge sev-${f.sev}">${Scanner.SEV[f.sev].label}</span>
          <span class="cat">${esc(Scanner.CAT[f.cat] || f.cat)}</span>
          <h3>${esc(f.title)}</h3>
        </div>
        <p class="f-desc">${esc(f.desc)}</p>
        ${f.line > 0 && f.lineText ? `<div class="snippet"><span class="ln">${f.line}行目</span><code>${snippet(f.lineText, f.col, f.matchLen)}</code></div>` : ''}
        ${f.decoded ? `<div class="decoded"><span>隠されていた内容</span><code>${visualize(f.decoded)}</code></div>` : ''}
        ${f.more ? `<p class="more">ほか同様の箇所が ${f.more} 件</p>` : ''}
      </li>`;
  }

  // 行の該当箇所付近を切り出し、見えない文字を可視化して表示
  function snippet(line, col, len) {
    const WIN = 220;
    let start = 0, end = line.length;
    if (line.length > WIN) {
      const c = Math.max(0, col);
      start = Math.max(0, c - 70);
      end = Math.min(line.length, Math.max(c + (len || 0) + 60, start + WIN));
      if (start > 0) while (start < line.length && isLowSurrogate(line.charCodeAt(start))) start++;
      if (end < line.length) while (end > start && isLowSurrogate(line.charCodeAt(end))) end--;
    }
    const s = col >= 0 && len ? col : -1;
    const e = s >= 0 ? s + len : -1;
    let html = start > 0 ? '<span class="ellipsis">…</span>' : '';
    if (s >= start && s < end) {
      html += visualize(line.slice(start, s)) + '<mark>' + visualize(line.slice(s, Math.min(e, end))) + '</mark>' + visualize(line.slice(Math.min(e, end), end));
    } else {
      html += visualize(line.slice(start, end));
    }
    if (end < line.length) html += '<span class="ellipsis">…</span>';
    return html;
  }

  const isLowSurrogate = (c) => c >= 0xDC00 && c <= 0xDFFF;

  function visualize(str) {
    let out = '';
    let tagRun = '';
    const flushTags = () => {
      if (!tagRun) return;
      out += `<span class="inv tag" title="不可視のタグ文字">⟦隠し: ${esc(tagRun)}⟧</span>`;
      tagRun = '';
    };
    for (const ch of str) {
      const cp = ch.codePointAt(0);
      if (cp >= 0xE0000 && cp <= 0xE007F) {
        tagRun += cp >= 0xE0020 && cp <= 0xE007E ? String.fromCharCode(cp - 0xE0000) : '';
        continue;
      }
      flushTags();
      if (Scanner.isInvisible(cp)) {
        out += `<span class="inv" title="見えない文字">U+${cp.toString(16).toUpperCase().padStart(4, '0')}</span>`;
      } else if (ch === '\t') {
        out += '<span class="ws">→</span>';
      } else {
        out += esc(ch);
      }
    }
    flushTags();
    return out;
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
})();
