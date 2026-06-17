// Mobile nav toggle
const toggle = document.querySelector('.nav-toggle');
const navLinks = document.querySelector('.nav-links');

if (toggle && navLinks) {
  toggle.addEventListener('click', () => {
    const open = navLinks.classList.toggle('is-open');
    toggle.setAttribute('aria-expanded', String(open));
  });

  // Close on link click
  navLinks.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', () => {
      navLinks.classList.remove('is-open');
      toggle.setAttribute('aria-expanded', 'false');
    });
  });

  // Close on outside click
  document.addEventListener('click', e => {
    if (!e.target.closest('.site-nav')) {
      navLinks.classList.remove('is-open');
      toggle.setAttribute('aria-expanded', 'false');
    }
  });
}

// Copy code blocks on click
document.querySelectorAll('pre code').forEach(block => {
  const pre = block.parentElement;
  const btn = document.createElement('button');
  btn.textContent = 'copy';
  btn.className = 'copy-btn';
  btn.setAttribute('aria-label', 'Copy code');

  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(block.textContent);
      btn.textContent = 'copied';
      setTimeout(() => { btn.textContent = 'copy'; }, 1800);
    } catch {
      btn.textContent = 'error';
    }
  });

  pre.style.position = 'relative';
  pre.appendChild(btn);
});

// Terminal-block highlighting.
// Rouge leaves untagged ``` fences (shell sessions, readelf/strings output, IOC
// dumps) as plain monochrome text. This enriches only those: the command line
// pops in the accent, hashes / hex offsets tint, and aligned inline annotations
// (# … or <- …) recede. Language-tagged blocks already carry Rouge token spans,
// so they are detected and skipped. Span wrapping does not change textContent,
// so the copy button still yields the raw command.
const TK_HEX = /(0x[0-9a-fA-F]{3,}|\b[0-9a-f]{40}\b|\b[0-9a-f]{64}\b)/g;
const TK_ANN = /(\s{2,}(?:#|&lt;-).*)$/;
document.querySelectorAll('pre > code').forEach(code => {
  if (code.querySelector('span')) return;            // Rouge-tagged: leave it alone
  code.innerHTML = code.innerHTML.split('\n').map(line => {
    const cmd = line.match(/^(\s*)(\$\s.*)$/);       // shell prompt: "$ …"
    if (cmd) {
      const body = cmd[2].replace(TK_ANN, '<span class="tk-ann">$1</span>');
      return `${cmd[1]}<span class="tk-cmd">${body}</span>`;
    }
    if (/^\s*#/.test(line)) return `<span class="tk-ann">${line}</span>`;  // full comment line
    return line
      .replace(TK_HEX, '<span class="tk-hex">$1</span>')
      .replace(TK_ANN, '<span class="tk-ann">$1</span>');
  }).join('\n');
});
