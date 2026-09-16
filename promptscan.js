/* =====================================================================
   SAVESAVESAVESAVE — PROMPT SAFETY SCAN (deterministic core)

   Analyses a prompt the user copied from somewhere and reports what it
   is asking an AI system — and the user — to do.

   ARCHITECTURE: this runs entirely in the browser. The submitted prompt
   never leaves the visitor's machine. There is no endpoint, no database,
   no third-party model. That is a deliberate product decision, not a
   limitation we are working around: a tool that tells people not to
   paste secrets into AI systems should not itself ship their text to a
   server. It also means there is nothing to log, retain, or disclose.

   THE SUBMITTED PROMPT IS DATA, NEVER INSTRUCTIONS. Nothing in this file
   evaluates it, fetches from it, or branches on what it asks for. It is
   string input to a set of pattern matchers, the same way a spam filter
   treats an email.

   Verdict vocabulary matches the address scanner: PASS / CAUTION / FAIL /
   INSUFFICIENT DATA, with the same rule that missing analysis never
   silently becomes PASS.
   ===================================================================== */

// ---------------------------------------------------------------- limits
// Every bound here exists so that hostile input cannot turn the scanner
// into a denial-of-service against the person running it.
const LIMITS = {
  MAX_INPUT_CHARS: 200000,     // beyond this we truncate and say so
  MAX_DECODE_DEPTH: 2,         // base64 inside base64, and no deeper
  MAX_DECODE_EXPANSION: 20000, // a decoded blob larger than this is not inspected
  MAX_DECODE_CANDIDATES: 40,   // stop hunting for encoded blobs after this many
  MAX_URLS: 200,
  EXCERPT_RADIUS: 60,          // characters of context shown either side
};

const SEVERITY_ORDER = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

// ---------------------------------------------------------- unicode sets
const ZERO_WIDTH = {
  '​': 'zero-width space',
  '‌': 'zero-width non-joiner',
  '‍': 'zero-width joiner',
  '⁠': 'word joiner',
  '﻿': 'byte-order mark',
};
const BIDI = {
  '‪': 'left-to-right embedding',
  '‫': 'right-to-left embedding',
  '‬': 'pop directional formatting',
  '‭': 'left-to-right override',
  '‮': 'right-to-left override',
  '⁦': 'left-to-right isolate',
  '⁧': 'right-to-left isolate',
  '⁨': 'first strong isolate',
  '⁩': 'pop directional isolate',
};
// U+E0000–U+E007F. Invisible to every renderer, carried through copy-paste,
// and readable by a model. The canonical way to hide an instruction in
// plain sight.
const TAGS_BLOCK = /[\u{E0000}-\u{E007F}]/u;

// Cyrillic and Greek letters that are visually identical to Latin ones.
const CONFUSABLES = {
  'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x',
  'у':'y','і':'i','ј':'j','һ':'h','ԁ':'d','ԛ':'q',
  'α':'a','ο':'o','ρ':'p','ν':'v','υ':'u','Α':'A',
  'Β':'B','Ε':'E','Ζ':'Z','Η':'H','Ι':'I','Κ':'K',
  'Μ':'M','Ν':'N','Ο':'O','Ρ':'P','Τ':'T','Χ':'X',
};

// ------------------------------------------------------------- utilities
function clampExcerpt(text, start, end) {
  const a = Math.max(0, start - LIMITS.EXCERPT_RADIUS);
  const b = Math.min(text.length, end + LIMITS.EXCERPT_RADIUS);
  return (a > 0 ? '…' : '') + text.slice(a, b).replace(/\s+/g, ' ').trim() + (b < text.length ? '…' : '');
}

function makeFinding(o) {
  return {
    ruleId: o.ruleId,
    category: o.category,
    severity: o.severity,
    confidence: o.confidence,
    title: o.title,
    plain: o.plain,
    technical: o.technical || '',
    evidence: o.evidence || null,
    action: o.action,
    source: o.source || 'deterministic',
    contributed: false,
  };
}

// --------------------------------------------------------------- stage 1
// Normalisation. The original text is never mutated — every finding
// carries an offset into what the user actually pasted, so the UI can
// highlight the real characters rather than a cleaned-up copy.
function analyseUnicode(text) {
  const findings = [];
  const strippedChars = [];

  const zwHits = [];
  const bidiHits = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ZERO_WIDTH[ch]) { zwHits.push({ i, ch, name: ZERO_WIDTH[ch] }); strippedChars.push(i); }
    else if (BIDI[ch]) { bidiHits.push({ i, ch, name: BIDI[ch] }); strippedChars.push(i); }
  }

  // A BOM at position 0 is normal file encoding, not an attack.
  const meaningfulZw = zwHits.filter(h => !(h.ch === '﻿' && h.i === 0));

  if (meaningfulZw.length) {
    const density = meaningfulZw.length / Math.max(1, text.length);
    const names = [...new Set(meaningfulZw.map(h => h.name))];
    findings.push(makeFinding({
      ruleId: 'UNICODE_ZEROWIDTH_001',
      category: 'UNICODE_OBFUSCATION',
      severity: meaningfulZw.length >= 8 || density > 0.01 ? 'HIGH' : 'MEDIUM',
      confidence: 0.95,
      title: `${meaningfulZw.length} invisible character${meaningfulZw.length === 1 ? '' : 's'} found`,
      plain: 'This prompt contains characters you cannot see. They render as nothing but are still read by an AI system, so the text a model receives is not the text on your screen.',
      technical: `Found: ${names.join(', ')}. First at offset ${meaningfulZw[0].i}.`,
      evidence: { excerpt: clampExcerpt(text, meaningfulZw[0].i, meaningfulZw[0].i + 1), start: meaningfulZw[0].i, end: meaningfulZw[0].i + 1, fromNormalized: false },
      action: 'Do not use this prompt as-is. Retype it by hand rather than pasting, or ask whoever published it why it contains invisible characters.',
      source: 'unicode',
    }));
  }

  if (bidiHits.length) {
    const overrides = bidiHits.filter(h => h.ch === '‮' || h.ch === '‭');
    findings.push(makeFinding({
      ruleId: 'UNICODE_BIDI_001',
      category: 'UNICODE_OBFUSCATION',
      severity: overrides.length ? 'HIGH' : 'MEDIUM',
      confidence: 0.9,
      title: 'Text-direction override characters found',
      plain: 'This prompt contains characters that change the order text is displayed in. They can make a line read one way on screen while saying something different underneath.',
      technical: `Found: ${[...new Set(bidiHits.map(h => h.name))].join(', ')}.`,
      evidence: { excerpt: clampExcerpt(text, bidiHits[0].i, bidiHits[0].i + 1), start: bidiHits[0].i, end: bidiHits[0].i + 1, fromNormalized: false },
      action: 'Treat the visible text as unreliable. Do not use this prompt without seeing it in a viewer that exposes control characters.',
      source: 'unicode',
    }));
  }

  if (TAGS_BLOCK.test(text)) {
    const m = text.match(TAGS_BLOCK);
    const idx = text.indexOf(m[0]);
    findings.push(makeFinding({
      ruleId: 'UNICODE_TAGS_001',
      category: 'UNICODE_OBFUSCATION',
      severity: 'CRITICAL',
      confidence: 0.97,
      title: 'Hidden instructions encoded in Unicode Tags characters',
      plain: 'This prompt contains characters from a Unicode block that is invisible in every normal application but is still read by AI systems. There is no legitimate everyday reason for text you copied off the internet to contain these.',
      technical: `Unicode Tags block (U+E0000–U+E007F) detected at offset ${idx}. This block is the standard carrier for instructions hidden inside apparently plain text.`,
      evidence: { excerpt: clampExcerpt(text, idx, idx + 1), start: idx, end: idx + 1, fromNormalized: false },
      action: 'Do not use this prompt. This is a deliberate concealment technique, not an accident of formatting.',
      source: 'unicode',
    }));
  }

  // Confusables: only interesting when a non-Latin letter sits inside an
  // otherwise-Latin word. Legitimate multilingual text is not flagged,
  // because whole words in Cyrillic or Greek never trip this.
  const mixedWords = [];
  const wordRe = /[A-Za-zЀ-ӿͰ-Ͽ]{3,40}/g;
  let wm;
  while ((wm = wordRe.exec(text)) !== null) {
    const w = wm[0];
    const latin = (w.match(/[A-Za-z]/g) || []).length;
    const conf = [...w].filter(c => CONFUSABLES[c]).length;
    if (latin > 0 && conf > 0) mixedWords.push({ word: w, index: wm.index, conf });
    if (mixedWords.length > 20) break;
  }
  if (mixedWords.length) {
    const first = mixedWords[0];
    findings.push(makeFinding({
      ruleId: 'UNICODE_CONFUSABLE_001',
      category: 'UNICODE_OBFUSCATION',
      severity: 'MEDIUM',
      confidence: 0.8,
      title: `Look-alike characters inside ${mixedWords.length} word${mixedWords.length === 1 ? '' : 's'}`,
      plain: 'Some words mix normal letters with letters from another alphabet that look identical. This is how a fake web address or brand name is made to look real.',
      technical: `e.g. "${first.word}" at offset ${first.index} contains ${first.conf} Cyrillic/Greek look-alike character(s) among Latin letters.`,
      evidence: { excerpt: clampExcerpt(text, first.index, first.index + first.word.length), start: first.index, end: first.index + first.word.length, fromNormalized: false },
      action: 'Check any web address or brand name in this prompt character by character before trusting it.',
      source: 'unicode',
    }));
  }

  const visible = text.replace(/[​-‍⁠﻿‪-‮⁦-⁩]/g, '')
                      .replace(/[\u{E0000}-\u{E007F}]/gu, '');

  return { findings, visible, strippedCount: strippedChars.length, changed: visible !== text };
}

// --------------------------------------------------------------- stage 2
// Markup: things a renderer hides but a model still reads.
function analyseMarkup(text) {
  const findings = [];
  let looksLikeMarkup = false;

  const htmlComments = [...text.matchAll(/<!--([\s\S]{0,4000}?)-->/g)];
  if (htmlComments.length) {
    looksLikeMarkup = true;
    const withInstructions = htmlComments.filter(m => directiveScore(m[1]).isDirective);
    if (withInstructions.length) {
      const m = withInstructions[0];
      findings.push(makeFinding({
        ruleId: 'HIDDEN_COMMENT_001',
        category: 'HIDDEN_MARKUP',
        severity: 'HIGH',
        confidence: 0.88,
        title: 'Instructions hidden inside an HTML comment',
        plain: 'Part of this prompt is inside a comment. Comments are invisible when a page is displayed but are still passed to an AI system as text — and this one contains instructions, not notes.',
        technical: `HTML comment at offset ${m.index} contains directive language.`,
        evidence: { excerpt: clampExcerpt(text, m.index, m.index + m[0].length), start: m.index, end: m.index + m[0].length, fromNormalized: false },
        action: 'Read the commented-out section before using this prompt. It is the part you were not meant to see.',
        source: 'markup',
      }));
    } else {
      findings.push(makeFinding({
        ruleId: 'HIDDEN_COMMENT_002',
        category: 'HIDDEN_MARKUP',
        severity: 'LOW',
        confidence: 0.6,
        title: `${htmlComments.length} HTML comment${htmlComments.length === 1 ? '' : 's'} present`,
        plain: 'This prompt contains commented-out text. It will not display, but an AI system still reads it. Nothing in it looked like an instruction.',
        technical: 'Comments found but none matched directive patterns.',
        evidence: { excerpt: clampExcerpt(text, htmlComments[0].index, htmlComments[0].index + htmlComments[0][0].length), start: htmlComments[0].index, end: htmlComments[0].index + htmlComments[0][0].length, fromNormalized: false },
        action: 'Worth reading the hidden section so you know what is in the prompt.',
        source: 'markup',
      }));
    }
  }

  // CSS that renders text invisible.
  const hideRe = /(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*(?:#fff(?:fff)?|white)\s*;?[^}]{0,80}background\s*:\s*(?:#fff(?:fff)?|white))/i;
  const hideM = text.match(hideRe);
  if (hideM) {
    looksLikeMarkup = true;
    findings.push(makeFinding({
      ruleId: 'HIDDEN_CSS_001',
      category: 'HIDDEN_MARKUP',
      severity: 'HIGH',
      confidence: 0.85,
      title: 'Styling that makes text invisible',
      plain: 'This prompt contains styling whose only purpose is to hide text from a reader while leaving it readable by software.',
      technical: `Matched: ${hideM[0].slice(0, 60)}`,
      evidence: { excerpt: clampExcerpt(text, hideM.index, hideM.index + hideM[0].length), start: hideM.index, end: hideM.index + hideM[0].length, fromNormalized: false },
      action: 'Do not use this prompt without viewing its raw source.',
      source: 'markup',
    }));
  }

  // Markdown link whose visible text is a different destination than its href.
  const mdLinks = [...text.matchAll(/\[([^\]\n]{1,200})\]\(([^)\s]{1,500})\)/g)];
  for (const m of mdLinks.slice(0, 30)) {
    const label = m[1].trim();
    const href = m[2].trim();
    const labelHost = hostOf(label);
    const hrefHost = hostOf(href);
    if (labelHost && hrefHost && !sameSite(labelHost, hrefHost)) {
      findings.push(makeFinding({
        ruleId: 'LINK_MISMATCH_001',
        category: 'PHISHING_INDICATOR',
        severity: 'HIGH',
        confidence: 0.9,
        title: 'A link displays one address and goes to another',
        plain: `The link text says "${labelHost}" but it actually goes to "${hrefHost}". That mismatch is the oldest trick in phishing.`,
        technical: `Markdown link at offset ${m.index}: label host ${labelHost}, destination host ${hrefHost}.`,
        evidence: { excerpt: clampExcerpt(text, m.index, m.index + m[0].length), start: m.index, end: m.index + m[0].length, fromNormalized: false },
        action: 'Do not open this link. Type the address you actually want into your browser instead.',
        source: 'markup',
      }));
      break;
    }
  }

  if (/<\/?[a-z][\w-]*\s*[^>]{0,200}>/i.test(text)) looksLikeMarkup = true;

  return { findings, looksLikeMarkup };
}

function hostOf(s) {
  const m = String(s).match(/\b((?:[a-z0-9¡-￿-]{1,63}\.){1,8}[a-z¡-￿]{2,24})\b/i);
  return m ? m[1].toLowerCase() : null;
}
function registrable(host) {
  const parts = String(host).split('.');
  return parts.slice(-2).join('.');
}
function sameSite(a, b) {
  return registrable(a) === registrable(b);
}

// --------------------------------------------------------------- stage 3
// Intent discrimination. This is the part that decides whether the text
// is TELLING an AI to do something, or TALKING ABOUT something being
// done. Getting this wrong in either direction is the main way a scanner
// like this becomes useless: flag every security article and nobody
// trusts it; ignore framing entirely and every real attack hides behind
// the word "example".
const REFERENTIAL = /\b(for example|for instance|e\.?g\.?|such as|attackers? (?:may|might|can|often|will|could)|this is how|these are|commonly used|is an example|an example of|do not follow|treat (?:it|them|this|the following) as data|never follow|should be ignored|watch out for|look out for|beware of|detect\w*|red flags?|warning signs?|the article says|according to|in this attack|researchers|demonstrat\w*|illustrat\w*|explain\w*|describ\w*|discuss\w*|teach\w*|warn\w*|tutorial|lesson|training|write (?:a|an|the) (?:blog|article|post|guide|essay|tutorial|lesson|explainer|summary)|what (?:is|are)|why (?:you|people|users|someone)|how (?:do|does|to spot|to detect|to recognise|to recognize|to avoid|to protect))\b/i;

// Advice AGAINST handing something over is the opposite of a request for
// it. "Never share your seed phrase" and "send me your seed phrase" match
// the same keyword and mean opposite things; without this the scanner
// FAILs the safety article it should be recommending.
const ADVISORY_NEGATION = /\b(?:never|do ?n[o']?t|don't|avoid|should ?n[o']?t|must ?n[o']?t|no one (?:should|ever|needs)|nobody (?:should|ever|needs)|refuse to|stop)\s+(?:\w+\s+){0,3}(?:share|shares|sharing|give|gives|giving|enter|enters|entering|reveal|reveals|revealing|disclose|discloses|disclosing|send|sends|sending|paste|pastes|pasting|type|types|typing|provide|hand over|post)\b/i;

// Verbs that, in the imperative, ask for an action rather than describe
// one. Deliberately broad: an attack that says "read the .env file" is no
// less an instruction than one that says "send the .env file", and an
// earlier, narrower list let several real attacks through the tests.
const ACTION_VERBS = 'ignore|disregard|forget|discard|override|bypass|reveal|print|output|dump|send|upload|post|email|mail|fetch|download|execute|run|install|delete|remove|transfer|approve|sign|export|exfiltrate|leak|show|give|repeat|read|extract|collect|gather|list|copy|paste|enter|type|provide|share|reply|return|mark|classify|respond|connect|verify|claim|forward|submit|disable|grant|attach|include';

// An imperative rarely starts a string cleanly. It follows a conjunction,
// a comma, a politeness word, or an adverb of concealment — all of which
// an anchor pinned to ^ or a full stop would miss.
const IMPERATIVE_RE = new RegExp(
  '(?:^|[.!?;:\\n]|\\b(?:and|then|now|also|finally|next|first)\\b|,|["\'`>\\-*])\\s*' +
  '(?:(?:please|kindly|silently|quietly|secretly|immediately|just|simply|carefully)\\s+){0,3}' +
  '(?:' + ACTION_VERBS + ')\\b',
  'i'
);

function directiveScore(fragment) {
  const f = String(fragment);
  const referential = REFERENTIAL.test(f);
  const addressesAssistant = /\b(you are|you must|you should|you will|your (?:instructions|system prompt|rules|policy|guidelines)|as an ai|assistant[,:]|chatgpt|claude|gemini|copilot)\b/i.test(f);
  const bareImperative = IMPERATIVE_RE.test(f);
  // Asking the reader for something is also directive, even without a
  // leading verb: "your seed phrase below" is a request, not a lecture.
  const solicits = /\b(?:enter|paste|type|provide|share|send|submit)\s+(?:your|the)\b|\bbelow\s*[:.]?\s*$/i.test(f);
  const score = (addressesAssistant ? 0.5 : 0) + (bareImperative ? 0.5 : 0) + (solicits ? 0.3 : 0) - (referential ? 0.6 : 0);
  return { isDirective: score > 0.3, score, referential, addressesAssistant, bareImperative, solicits };
}

// A rule is {id, category, severity, confidence, re, title, plain, action,
// requiresDirective}. `requiresDirective` means the match only counts when
// the surrounding sentence is actually instructing, not describing.
const RULES = [
  {
    id: 'PROMPT_OVERRIDE_001', category: 'PROMPT_INJECTION', severity: 'HIGH', confidence: 0.9,
    re: /\b(ignore|disregard|forget|discard)\s+(?:all\s+|any\s+|the\s+|your\s+|previous\s+|prior\s+|earlier\s+|above\s+){0,3}(instructions?|prompts?|rules?|directives?|guidelines?|messages?|context)\b/i,
    title: 'Tells the AI to ignore its existing instructions',
    plain: 'This prompt tries to cancel whatever rules the AI system was already operating under. Legitimate prompts ask for something; they do not need to disable what came before.',
    action: 'Do not paste this into an AI system that has access to your files, accounts, or tools.',
    requiresDirective: true,
  },
  {
    id: 'PROMPT_OVERRIDE_002', category: 'PROMPT_INJECTION', severity: 'HIGH', confidence: 0.85,
    re: /\b(you are now|from now on,? you|act as if you (?:are|have)|pretend (?:you are|to be)|you have no (?:restrictions|limits|rules|filters)|unrestricted mode|developer mode|jailbreak|dan mode|no longer bound)\b/i,
    title: 'Tries to redefine what the AI is',
    plain: 'The prompt attempts to give the AI a new identity or remove its limits. This is the standard opening move for getting a system to do something it would normally decline.',
    action: 'Treat anything this prompt produces as unreliable, and do not give it access to private data.',
    requiresDirective: false,
  },
  {
    // Persona jailbreaks. The distinguishing feature is not roleplay —
    // roleplay is a normal, useful thing to ask for — but roleplay whose
    // stated purpose is the removal of limits.
    id: 'PROMPT_OVERRIDE_003', category: 'PROMPT_INJECTION', severity: 'HIGH', confidence: 0.85,
    re: /\b(?:roleplay|role-play|act|pretend|imagine|simulate|you\s+are)\b[^.!?\n]{0,120}\b(?:no|without|free\s+from|ignores?|bypasses?)\s+(?:content\s+)?(?:policy|policies|filter|filters|restrictions?|limits?|limitations?|guidelines?|guardrails?|rules?|safety)\b|\b(?:stay|remain)\s+in\s+character\b[^.!?\n]{0,60}\b(?:no matter|regardless|whatever)\b|\b(?:DAN|do anything now|evil\s?(?:gpt|bot)|[a-z]{2,10}gpt)\b[^.!?\n]{0,60}\bno\s+(?:content\s+)?(?:policy|filter|restrictions?)\b/i,
    title: 'A persona whose point is removing the AI\'s limits',
    plain: 'The prompt asks the system to play a character defined by not having rules. Asking for a character is ordinary; asking for one whose defining trait is having no restrictions is a jailbreak.',
    action: 'Whatever this prompt produces is unreliable. Do not give it access to private data or tools.',
    requiresDirective: false,
  },
  {
    // A fake system-message marker. Real system instructions never arrive
    // inside text a user pasted.
    id: 'FAKE_SYSTEM_MESSAGE_001', category: 'PROMPT_INJECTION', severity: 'HIGH', confidence: 0.88,
    re: /(?:\[|<|#{2,}|\*{2,})\s*(?:SYSTEM|ADMIN|DEVELOPER|ROOT|OVERRIDE|SYSTEM\s+OVERRIDE|NEW\s+(?:DIRECTIVE|INSTRUCTIONS?)|IMPORTANT\s+SYSTEM)\s*(?:OVERRIDE|MESSAGE|PROMPT|NOTE|DIRECTIVE)?\s*(?:\]|>|#{2,}|\*{2,}|:)|<\|im_start\|>\s*system|<\|system\|>|^\s*system\s*:/im,
    title: 'Imitates a system or developer message',
    plain: 'Part of this prompt is dressed up to look like a privileged instruction from the software itself. It is not — it is ordinary text you pasted, with no more authority than the rest.',
    action: 'Ignore the claimed authority. Judge the prompt by what it actually asks for.',
    requiresDirective: false,
  },
  {
    id: 'INSTRUCTION_REPLACEMENT_001', category: 'PROMPT_INJECTION', severity: 'HIGH', confidence: 0.85,
    re: /\byour\s+new\s+(?:system\s+)?(?:prompt|instructions?|directive|rules?|task)\s+(?:is|are)\b|\breplace\s+your\s+(?:instructions?|system\s+prompt|rules)\b|\bupdated?\s+(?:system\s+)?(?:prompt|instructions?)\s*:/i,
    title: 'Tries to install itself as the AI\'s new instructions',
    plain: 'The prompt announces a replacement set of rules for the AI to follow. Instructions that arrive inside user text are not instructions — but a system that mistakes them for some is exactly what this is aiming at.',
    action: 'Do not use this prompt in any assistant that holds private context or can take actions.',
    requiresDirective: false,
  },
  {
    // Deferred execution: "do X, then do whatever X says". The payload is
    // not in the prompt, which is the point.
    id: 'DEFERRED_EXECUTION_001', category: 'INDIRECT_INJECTION', severity: 'HIGH', confidence: 0.85,
    re: /\b(?:then|and|afterwards?|next)\s+(?:execute|run|follow|obey|carry\s+out|do|perform|apply)\s+(?:whatever|any|the|all|those|these)\s+(?:it|they|that|instructions?|commands?|steps?|directions?)\b|\bfollow\s+(?:any|all|the)\s+instructions?\s+(?:in|inside|within|contained\s+in|found\s+in)\b|\bdo\s+(?:whatever|what)\s+(?:it|the\s+\w{1,20})\s+says\b/i,
    title: 'Tells the AI to obey instructions it has not seen yet',
    plain: 'The prompt asks the system to follow whatever instructions turn up in some other content — a document, a translation, a web page. That hands control to whoever wrote that content instead of to you.',
    action: 'Do not use this prompt. Instruct the assistant to treat fetched or translated content as data, never as commands.',
    requiresDirective: false,
  },
  {
    // Data appended to a URL — the image-pixel exfiltration pattern. The
    // request is never "send data"; it is "load this picture".
    id: 'URL_APPEND_EXFIL_001', category: 'DATA_EXFILTRATION', severity: 'HIGH', confidence: 0.85,
    re: /\b(?:append|add|include|attach|concatenate|put|encode)\s+(?:the\s+)?[^.!?\n]{0,60}?\b(?:to|into|in|onto)\s+(?:the\s+)?(?:image\s+)?(?:url|link|address|src|query|parameter|endpoint)\b|\b(?:image|img|pixel|gif|png)\s+(?:url|src|link)[^.!?\n]{0,40}\?\w{1,20}=\s*$|!\[[^\]]*\]\(https?:\/\/[^)\s]{0,200}\?\w{1,20}=/i,
    title: 'Data is being smuggled out through a link or image address',
    plain: 'The prompt attaches information to the end of a web address. When the AI or your browser loads that address, the data goes to whoever owns it — no obvious "send" step required.',
    action: 'Do not use this prompt. This is exfiltration disguised as loading an image.',
    requiresDirective: false,
  },
  {
    id: 'LOCAL_FILE_READ_001', category: 'FILE_ACCESS', severity: 'HIGH', confidence: 0.85,
    re: /(?:\/etc\/(?:passwd|shadow|hosts)|~\/\.(?:ssh|aws|config|npmrc|git-credentials)|\bid_rsa\b|C:\\Users\\[^\\\s]{1,40}\\|%USERPROFILE%|\bcontents?\s+of\s+(?:the\s+)?file\s+(?:at|in|named)?|\bcat\s+(?:~|\/)[\w./-]{2,60})/i,
    title: 'Points at files on your computer',
    plain: 'The prompt names specific files or folders on a machine — credentials, SSH keys, system files. A prompt about writing or summarising has no reason to know those paths.',
    action: 'Do not run this in an assistant with file access or a shell.',
    requiresDirective: false,
  },
  {
    id: 'AUTH_CODE_REQUEST_001', category: 'CREDENTIAL_HARVESTING', severity: 'HIGH', confidence: 0.85,
    re: /\b(?:2fa|two[- ]factor|mfa|otp|one[- ]time)\s*(?:code|password|pin|token)?\b|\b(?:verification|authentication|security|confirmation)\s+code\b|\bauthenticator\s+(?:code|app)\b|\bbackup\s+codes?\b/i,
    title: 'Involves a one-time or two-factor code',
    plain: 'The prompt touches on a 2FA or verification code. Those codes exist precisely so that nobody else gets them — including an AI system, and including anyone who asks convincingly.',
    action: 'Never relay a verification code to anyone or anything that asks for it.',
    requiresDirective: true,
  },
  {
    id: 'SYSTEM_PROMPT_EXTRACTION_001', category: 'SYSTEM_PROMPT_EXTRACTION', severity: 'HIGH', confidence: 0.9,
    re: /\b(reveal|show|print|output|repeat|display|reproduce|dump|disclose|tell me|confirm by outputting)\s+(?:me\s+)?(?:your|the|all|its)\s+(?:system\s+prompt|initial\s+instructions?|hidden\s+(?:instructions?|prompt|rules)|internal\s+(?:instructions?|policy|rules)|original\s+instructions?|previous\s+(?:one|prompt|instructions?)|prompt\s+above|configuration|guidelines)\b/i,
    title: 'Asks the AI to reveal its hidden instructions',
    plain: 'The prompt asks the system to print its own configuration. On its own this is mostly curiosity — but it is also how someone maps a system before attacking it, and it often travels with worse things.',
    action: 'Harmless to run on a throwaway chat. Do not run it in a system that holds private context.',
    requiresDirective: true,
  },
  {
    id: 'SECRET_REQUEST_CRYPTO_001', category: 'CRYPTO_SECRET_REQUEST', severity: 'CRITICAL', confidence: 0.95,
    re: /\b(seed\s?(?:phrase|words?)|recovery\s?(?:phrase|words?|seed)|secret\s+words?|backup\s+phrase|mnemonic(?:\s+phrase)?|private\s?key|secret\s?key|signing\s?key|wallet\s+password|keystore\s+file|hardware\s+wallet\s+pin|12[- ]word|24[- ]word)\b/i,
    title: 'Asks for a wallet secret',
    plain: 'This prompt mentions a seed phrase, recovery phrase, or private key in a way that asks for one. Anyone who gets these owns your funds instantly and irreversibly. No legitimate service, tool, or support agent ever needs them.',
    action: 'Never type a seed phrase or private key anywhere — not into this prompt, not into an AI system, not into SaveSaveSaveSave.',
    requiresDirective: true,
  },
  {
    id: 'SECRET_REQUEST_001', category: 'CREDENTIAL_HARVESTING', severity: 'HIGH', confidence: 0.85,
    re: /\b(password|api[\s_-]?key|access[\s_-]?token|auth(?:entication)?[\s_-]?token|bearer\s+token|session\s+cookie|oauth\s+token|client[\s_-]?secret|credit\s?card|cvv|ssn|social\s+security\s+number)\b/i,
    title: 'Asks for credentials',
    plain: 'The prompt requests a password, key, or token. A prompt that genuinely needs to do something on your behalf asks you to authorise it — it does not ask you to hand over the key.',
    action: 'Do not supply the requested value. If a prompt needs credentials to work, that is the prompt\'s problem, not yours to solve.',
    requiresDirective: true,
  },
  {
    id: 'PRIVATE_CONTEXT_001', category: 'SENSITIVE_DATA_REQUEST', severity: 'HIGH', confidence: 0.85,
    re: /\b(environment\s+variables?|\.env\b|process\.env|browser\s+(?:history|cookies?)|local\s?storage|ssh\s+keys?|id_rsa|\.aws\/credentials|saved\s+passwords?|keychain|credential\s+(?:store|manager)|clipboard\s+contents?|read\s+(?:the\s+)?(?:file|files|documents?)\s+(?:in|from|at))\b/i,
    title: 'Asks the AI to read private data from your machine',
    plain: 'The prompt tries to get an AI system to pull data out of your computer or browser — environment variables, cookies, saved keys, local files. That data is not part of the task you thought you were running.',
    action: 'Do not run this in any assistant that has file access, a browser extension, or shell access.',
    requiresDirective: true,
  },
  {
    id: 'EXFILTRATION_001', category: 'DATA_EXFILTRATION', severity: 'HIGH', confidence: 0.88,
    // A destination can be a URL, a bare host, a webhook, OR an email
    // address — an early version matched only URLs, and a prompt that
    // mailed an SSH key to an address walked straight past it.
    re: /\b(send|post|upload|transmit|forward|exfiltrate|report|submit|deliver|sync|email|mail)\s+(?:it|them|this|that|me|the\s+(?:result|output|data|contents?|file|info(?:rmation)?|key|phrase|text)|all\s+\w{1,20}|your\s+\w{1,20}|the\s+above|the\s+contents?\s+of\s+\S{1,60})?\s*(?:to|into|at|via)\s+(?:https?:\/\/|www\.|[a-z0-9-]+\.[a-z]{2,}|[\w.+-]{1,64}@[\w-]{1,63}\.[a-z]{2,24}|this\s+(?:url|link|endpoint|address|webhook|bot)|my\s+(?:server|email|bot|webhook|endpoint)|the\s+(?:following|url|link|endpoint|webhook))/i,
    title: 'Instructs data to be sent somewhere',
    plain: 'The prompt tells the AI to send information to an outside address. Whatever the prompt collects would leave your control at that point.',
    action: 'Do not use this prompt. Find out where that destination goes before trusting anything from the same source.',
    requiresDirective: true,
  },
  {
    id: 'EXFILTRATION_002', category: 'EXTERNAL_TRANSMISSION', severity: 'HIGH', confidence: 0.85,
    re: /\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|XMLHttpRequest|navigator\.sendBeacon|fetch\s*\(\s*['"`]https?:|requests\.(?:post|get)\s*\(|axios\.(?:post|get)\s*\()/,
    title: 'Contains code that makes a network request',
    plain: 'The prompt includes a command or snippet that sends data over the internet. In a prompt meant to be pasted into an AI assistant, that is rarely what it looks like.',
    action: 'Read exactly what is being sent and to where before running anything from this prompt.',
    requiresDirective: false,
  },
  {
    id: 'EXFILTRATION_003', category: 'DATA_EXFILTRATION', severity: 'MEDIUM', confidence: 0.75,
    re: /\b(telegram(?:\s+bot)?|discord\s+webhook|discordapp\.com\/api\/webhooks|hooks\.slack\.com|webhook\.site|requestbin|pipedream\.net|ngrok\.io|burpcollaborator)\b/i,
    title: 'Mentions a webhook or bot destination',
    plain: 'The prompt references a service commonly used to collect data quietly from somewhere else. Some of these have ordinary uses; in a prompt you were handed, they deserve a second look.',
    action: 'Check what data would reach that destination before using this prompt.',
    requiresDirective: false,
  },
  {
    id: 'DANGEROUS_COMMAND_001', category: 'DANGEROUS_COMMAND', severity: 'HIGH', confidence: 0.88,
    re: /\b(rm\s+-rf|del\s+\/[sf]|format\s+[a-z]:|Set-ExecutionPolicy|Set-MpPreference|Add-MpPreference\s+-ExclusionPath|disable\s+(?:antivirus|defender|firewall|gatekeeper|sip)|chmod\s+777|sudo\s+su|reg\s+add\s+HKLM|schtasks\s+\/create|crontab\s+-)\b/i,
    title: 'Contains a command that changes or damages your system',
    plain: 'The prompt includes a command that deletes files, disables a security control, or installs something persistent. None of that belongs in a prompt you copied off the internet.',
    action: 'Do not run this. Do not paste it into any assistant that can execute commands.',
    requiresDirective: false,
  },
  {
    id: 'CODE_EXECUTION_001', category: 'CODE_EXECUTION', severity: 'MEDIUM', confidence: 0.75,
    re: /\b(run|execute|eval)\s+(?:this|the following|these)\s+(?:command|script|code|snippet)|\b(?:bash|sh|powershell|cmd\.exe|python|node)\s+-c\b|\b(?:iex|iwr)\s*\(|\|\s*(?:bash|sh)\b/i,
    title: 'Asks for code to be executed',
    plain: 'The prompt asks an AI system or you to run code. Running code from an unknown source is how most compromises start.',
    action: 'Read the code line by line, or do not run it. If you cannot read it, do not run it.',
    requiresDirective: false,
  },
  {
    id: 'WALLET_ACTION_001', category: 'WALLET_ACTION', severity: 'CRITICAL', confidence: 0.9,
    re: /\b(sign\s+(?:this|the following|any)\s+(?:message|transaction|payload)|approve\s+(?:unlimited|infinite|max(?:imum)?)\s+(?:spend|allowance|token)|setApprovalForAll|increaseAllowance|transfer\s+(?:all\s+)?(?:your\s+)?(?:funds|tokens|assets|balance)|drain|sweep\s+(?:the\s+)?wallet)\b/i,
    title: 'Asks you to sign or approve a blockchain transaction',
    plain: 'The prompt pushes you toward signing a message or approving token spending. A single unlimited approval can empty a wallet later, without asking again.',
    action: 'Do not sign or approve anything based on a prompt you were given. Verify independently, in your own wallet, what you are approving.',
    requiresDirective: true,
  },
  {
    id: 'WALLET_CONNECT_001', category: 'PHISHING_INDICATOR', severity: 'HIGH', confidence: 0.8,
    re: /\b(connect\s+(?:your\s+)?wallet|validate\s+(?:your\s+)?wallet|verify\s+(?:your\s+)?wallet|sync\s+(?:your\s+)?wallet|restore\s+(?:your\s+)?wallet|import\s+(?:your\s+)?wallet|claim\s+(?:your\s+)?(?:airdrop|reward|tokens?)|migrate\s+(?:your\s+)?(?:funds|tokens))\b/i,
    title: 'Pushes you to connect or "verify" a wallet',
    plain: 'The prompt asks you to connect, verify, restore, or migrate a wallet, or to claim something. "Verify your wallet" is not a real procedure — it is the standard wrapper on a wallet-drainer.',
    action: 'Do not connect a wallet because a prompt told you to. Real services never need you to restore or verify a wallet to receive anything.',
    requiresDirective: true,
  },
  {
    id: 'SOCIAL_ENGINEERING_001', category: 'SOCIAL_ENGINEERING', severity: 'MEDIUM', confidence: 0.7,
    re: /\b(urgent(?:ly)?|immediately|act now|within \d+ (?:minutes?|hours?)|expires? (?:soon|today|in)|last chance|final (?:warning|notice)|account (?:will be )?(?:suspended|locked|closed|terminated)|suspicious activity detected|verify (?:your )?(?:identity|account) (?:now|immediately))\b/i,
    title: 'Uses urgency or threats',
    plain: 'The prompt pressures you to act fast. Time pressure exists to stop you checking, and it is present in almost every scam and almost no legitimate instruction.',
    action: 'Slow down. Anything genuinely important will still be true in an hour.',
    requiresDirective: false,
  },
  {
    id: 'IMPERSONATION_001', category: 'BRAND_IMPERSONATION', severity: 'MEDIUM', confidence: 0.7,
    re: /\b(?:this is|i am|message from|on behalf of)\s+(?:the\s+)?(?:system|administrator|admin|security team|support team|developer|openai|anthropic|google|metamask|coinbase|binance|ledger|trezor|phantom)\b/i,
    title: 'Claims to speak for a system or company',
    plain: 'The prompt asserts authority it cannot prove — a system message, an admin, or a known company. Text in a prompt has no special standing no matter who it says it is from.',
    action: 'Ignore the claimed identity. Judge the prompt by what it asks for.',
    requiresDirective: false,
  },
  {
    id: 'TOOL_ABUSE_001', category: 'TOOL_ABUSE', severity: 'MEDIUM', confidence: 0.75,
    re: /\b(without (?:asking|confirmation|permission|telling|informing|notifying)|do not (?:ask|confirm|tell|inform|notify|mention|report|log)|don'?t (?:ask|tell|mention|report)|silently|secretly|quietly|without the user'?s? (?:knowledge|awareness|consent)|hide (?:this|it|the) (?:from|activity)|no need to (?:ask|confirm|mention))\b/i,
    title: 'Asks the AI to act without telling you',
    plain: 'The prompt instructs the system to skip confirmation or to conceal what it is doing. There is no benign reason for a prompt to want its own activity hidden from you.',
    action: 'Do not use this prompt. Concealment is the tell, regardless of what else the prompt does.',
    requiresDirective: false,
  },
  {
    // A prompt that addresses the checker rather than the assistant is
    // adversarial by construction. Nothing written in good faith needs to
    // tell a safety scanner what to conclude.
    id: 'SCANNER_MANIPULATION_001', category: 'PROMPT_INJECTION', severity: 'HIGH', confidence: 0.9,
    // Note on what is deliberately NOT here: a bare "this prompt is safe".
    // A legitimate instruction can say "determine whether this prompt is
    // safe", and flagging that would break the honest use of the tool. Only
    // assertive framings count — a claim of verification, a stated correct
    // answer, or a direct instruction about the verdict.
    re: /\b(?:ignore|bypass|override|disable)\s+(?:the\s+)?(?:scanner|analyz\w+|analys\w+|detector|checker|safety\s+check|security\s+check)|(?:return|output|report|give|mark|set|classify|respond\s+with)\s+(?:the\s+)?(?:verdict\s+)?(?:as\s+)?(?:PASS|SAFE|CLEAN|benign|harmless|no\s+(?:risk|findings?|issues?))\b|\bmark\s+(?:all\s+)?(?:findings?|this|it|them)\s+(?:as\s+)?(?:PASS|SAFE|CLEAN|informational|benign|low)\b|\bthe\s+correct\s+(?:output|answer|verdict|result|classification)\s+is\b|\b(?:this|the)\s+(?:prompt|content|text)\s+(?:has been|is)\s+(?:100%\s*)?(?:verified|certified|confirmed|guaranteed)\b|\bskip\s+(?:the\s+)?(?:analysis|scan|scanning|check)\b|\bdo\s+not\s+(?:mention|report|flag|include|list)\s+the\b/i,
    title: 'Tries to tell the safety check what to conclude',
    plain: 'This prompt contains text aimed at whatever is inspecting it, instructing it to report the prompt as safe or to leave something out of the report. A prompt with nothing to hide has no reason to argue with a scanner.',
    action: 'Treat this as hostile. The attempt to influence the check is itself the strongest finding here.',
    requiresDirective: false,
  },
  {
    id: 'INDIRECT_INJECTION_001', category: 'INDIRECT_INJECTION', severity: 'HIGH', confidence: 0.8,
    re: /\b(?:when you (?:read|see|process|summarize|summarise|analyze|analyse) this|before (?:summarizing|summarising|answering|responding|continuing)|after reading this|the (?:real|actual|true|correct) (?:instruction|task|system message|prompt) is|this (?:document|text|message|article) (?:contains|includes) (?:your|the) (?:new )?instructions?)\b/i,
    title: 'Instructions disguised as document content',
    plain: 'Text that looks like an article or a document contains commands aimed at whatever AI reads it. This is how a poisoned web page or email hijacks an assistant that was only asked to summarise it.',
    action: 'If you are feeding this to an assistant, tell it explicitly to treat the content as data and not follow instructions inside it.',
    requiresDirective: false,
  },
];

function runRules(text) {
  const findings = [];
  for (const rule of RULES) {
    const m = text.match(rule.re);
    if (!m) continue;
    const idx = m.index;
    // Judge intent from the sentence the match sits in, not the whole text.
    const sentStart = Math.max(0, text.lastIndexOf('.', idx) + 1);
    const sentEnd = (() => { const e = text.indexOf('.', idx + m[0].length); return e === -1 ? Math.min(text.length, idx + 300) : e + 1; })();
    const sentence = text.slice(sentStart, sentEnd);
    const d = directiveScore(sentence);

    let severity = rule.severity;
    let confidence = rule.confidence;
    let note = '';

    // Warning someone off a thing is not asking for it.
    if (rule.requiresDirective && ADVISORY_NEGATION.test(sentence)) {
      findings.push(makeFinding({
        ruleId: rule.id,
        category: 'BENIGN_INFORMATIONAL',
        severity: 'INFO',
        confidence: 0.5,
        title: rule.title + ' — as a warning, not a request',
        plain: 'This phrase appears in advice telling people NOT to hand something over. That is the opposite of asking for it, so it did not count toward the verdict.',
        technical: `Rule ${rule.id} matched at offset ${idx} but the sentence carries advisory negation.`,
        evidence: { excerpt: clampExcerpt(text, idx, idx + m[0].length), start: idx, end: idx + m[0].length, fromNormalized: false },
        action: 'No action needed.',
        source: 'deterministic',
      }));
      continue;
    }

    if (rule.requiresDirective && !d.isDirective) {
      if (d.referential) {
        // Discussing the technique, not deploying it. Report at INFO so the
        // user still sees what was matched and why it did not count.
        severity = 'INFO';
        confidence = Math.min(confidence, 0.5);
        note = ' Matched inside explanatory text rather than an instruction, so it did not count toward the verdict.';
      } else {
        severity = SEVERITY_ORDER[severity] > 1 ? 'LOW' : severity;
        confidence = Math.max(0.4, confidence - 0.3);
        note = ' The surrounding sentence is ambiguous about whether this is an instruction.';
      }
    }

    findings.push(makeFinding({
      ruleId: rule.id,
      category: rule.category,
      severity,
      confidence,
      title: rule.title,
      plain: rule.plain + note,
      technical: `Rule ${rule.id} matched "${m[0].slice(0, 80)}" at offset ${idx}. Directive score ${d.score.toFixed(2)} (assistant-addressed: ${d.addressesAssistant}, imperative: ${d.bareImperative}, referential: ${d.referential}).`,
      evidence: { excerpt: clampExcerpt(text, idx, idx + m[0].length), start: idx, end: idx + m[0].length, fromNormalized: false },
      action: rule.action,
      source: 'deterministic',
    }));
  }
  return findings;
}

// --------------------------------------------------------------- stage 4
// URLs. Extracted and inspected structurally. Never fetched — a scanner
// that visits the addresses inside a hostile prompt is itself the attack.
const SHORTENERS = new Set(['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','cutt.ly','rb.gy','shorturl.at','rebrand.ly','t.ly','v.gd','tiny.cc','shorte.st','adf.ly','bl.ink','lnkd.in','db.tt','qr.ae','trib.al','x.co','soo.gd','clck.ru','tr.im']);
const BRANDS = ['metamask','coinbase','binance','ledger','trezor','phantom','uniswap','opensea','kraken','etherscan','trustwallet','exodus','blockchain','pancakeswap','solflare','openai','anthropic','google','microsoft','apple','paypal'];

function analyseUrls(text) {
  const findings = [];
  const urls = [];
  const re = /\b(?:https?:\/\/|www\.)[^\s<>"'`\])}]{2,500}/gi;
  let m;
  while ((m = re.exec(text)) !== null && urls.length < LIMITS.MAX_URLS) {
    const raw = m[0].replace(/[.,;:!?)\]]+$/, '');
    let u;
    try { u = new URL(raw.startsWith('http') ? raw : 'https://' + raw); } catch (_) { continue; }

    const host = u.hostname.toLowerCase();
    const info = {
      raw, normalized: u.href, scheme: u.protocol.replace(':', ''), host,
      port: u.port || null, path: u.pathname, hasQuery: !!u.search, hasFragment: !!u.hash,
      punycode: host.startsWith('xn--') || host.includes('.xn--'),
      ipHost: /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^\[?[0-9a-f:]+\]?$/i.test(host),
      shortener: SHORTENERS.has(registrable(host)),
      subdomainDepth: host.split('.').length,
      userinfo: !!(u.username || u.password),
      offset: m.index,
    };
    // A known brand that appears anywhere except the registrable domain.
    info.brandMisplaced = BRANDS.find(b =>
      (host.includes(b) && !registrable(host).startsWith(b)) ||
      (u.pathname.toLowerCase().includes(b) && !registrable(host).includes(b))
    ) || null;
    info.encodedParams = /%[0-9a-f]{2}/i.test(u.search) && u.search.length > 40;
    urls.push(info);
  }

  for (const u of urls) {
    if (u.userinfo) {
      findings.push(makeFinding({
        ruleId: 'URL_USERINFO_001', category: 'SUSPICIOUS_URL', severity: 'HIGH', confidence: 0.9,
        title: 'A link hides its real destination before an @ sign',
        plain: `This link looks like it goes to one place, but everything before the "@" is ignored by your browser. It actually goes to ${u.host}.`,
        technical: `URL with userinfo component at offset ${u.offset}: ${u.raw.slice(0, 100)}`,
        evidence: { excerpt: clampExcerpt(text, u.offset, u.offset + u.raw.length), start: u.offset, end: u.offset + u.raw.length, fromNormalized: false },
        action: 'Do not open this link.', source: 'url',
      }));
    }
    if (u.ipHost) {
      findings.push(makeFinding({
        ruleId: 'URL_IP_001', category: 'SUSPICIOUS_URL', severity: 'MEDIUM', confidence: 0.8,
        title: 'A link points at a bare IP address',
        plain: 'This link goes to a numeric address rather than a domain name. Legitimate services almost always use a name.',
        technical: `IP-literal host ${u.host} at offset ${u.offset}.`,
        evidence: { excerpt: clampExcerpt(text, u.offset, u.offset + u.raw.length), start: u.offset, end: u.offset + u.raw.length, fromNormalized: false },
        action: 'Do not open this link unless you know exactly whose machine that is.', source: 'url',
      }));
    }
    if (u.punycode) {
      findings.push(makeFinding({
        ruleId: 'URL_PUNYCODE_001', category: 'SUSPICIOUS_URL', severity: 'HIGH', confidence: 0.85,
        title: 'A link uses an encoded domain name',
        plain: 'This address is written in a format that can display as a completely different name in your browser. It is the standard way to fake a well-known domain.',
        technical: `Punycode host ${u.host} at offset ${u.offset}.`,
        evidence: { excerpt: clampExcerpt(text, u.offset, u.offset + u.raw.length), start: u.offset, end: u.offset + u.raw.length, fromNormalized: false },
        action: 'Do not open this link.', source: 'url',
      }));
    }
    if (u.shortener) {
      findings.push(makeFinding({
        ruleId: 'URL_SHORTENER_001', category: 'SUSPICIOUS_URL', severity: 'MEDIUM', confidence: 0.75,
        title: 'A shortened link hides where it goes',
        plain: 'Short links do not show their destination. We do not follow it — that would mean this scanner visiting an address a stranger chose.',
        technical: `Shortener ${u.host} at offset ${u.offset}. Not resolved by design.`,
        evidence: { excerpt: clampExcerpt(text, u.offset, u.offset + u.raw.length), start: u.offset, end: u.offset + u.raw.length, fromNormalized: false },
        action: 'Expand it with a link-preview service before opening it, or do not open it.', source: 'url',
      }));
    }
    if (u.brandMisplaced) {
      findings.push(makeFinding({
        ruleId: 'URL_BRAND_001', category: 'BRAND_IMPERSONATION', severity: 'HIGH', confidence: 0.8,
        title: `A link uses the name "${u.brandMisplaced}" but is not that site`,
        plain: `The real owner of a web address is the part just before the final dot — here that is "${registrable(u.host)}", not ${u.brandMisplaced}. Putting a trusted name elsewhere in the address is deliberate.`,
        technical: `Brand token "${u.brandMisplaced}" outside the registrable domain (${registrable(u.host)}) at offset ${u.offset}.`,
        evidence: { excerpt: clampExcerpt(text, u.offset, u.offset + u.raw.length), start: u.offset, end: u.offset + u.raw.length, fromNormalized: false },
        action: `Do not open this. Reach ${u.brandMisplaced} by typing its address yourself.`, source: 'url',
      }));
    }
    if (u.subdomainDepth >= 5) {
      findings.push(makeFinding({
        ruleId: 'URL_SUBDOMAIN_001', category: 'SUSPICIOUS_URL', severity: 'LOW', confidence: 0.6,
        title: 'A link has an unusually long address',
        plain: 'This address has many dotted parts, which is often used to push the real domain out of view on a phone.',
        technical: `Subdomain depth ${u.subdomainDepth} for ${u.host}.`,
        evidence: { excerpt: clampExcerpt(text, u.offset, u.offset + u.raw.length), start: u.offset, end: u.offset + u.raw.length, fromNormalized: false },
        action: `Read the part just before the final dot: ${registrable(u.host)}. That is who owns it.`, source: 'url',
      }));
    }
    if (u.encodedParams) {
      findings.push(makeFinding({
        ruleId: 'URL_ENCODED_PARAMS_001', category: 'DATA_EXFILTRATION', severity: 'MEDIUM', confidence: 0.7,
        title: 'A link carries a long encoded payload',
        plain: 'The address has a long scrambled section after the question mark. That is one way data gets carried out to somebody else\'s server.',
        technical: `Percent-encoded query of length ${u.raw.length} at offset ${u.offset}.`,
        evidence: { excerpt: clampExcerpt(text, u.offset, u.offset + u.raw.length), start: u.offset, end: u.offset + u.raw.length, fromNormalized: false },
        action: 'Do not open this link.', source: 'url',
      }));
    }
  }

  return { findings, urls };
}

// --------------------------------------------------------------- stage 5
// Decoding. Bounded, non-executing, and re-scanned with the same rules so
// an instruction hidden in base64 is caught by the detector it was hiding
// from.
function analyseEncoding(text) {
  const findings = [];
  const artifacts = [];

  const tryDecode = (s, kind) => {
    try {
      let out;
      if (kind === 'base64') {
        if (typeof atob === 'function') out = atob(s);
        else out = Buffer.from(s, 'base64').toString('utf8');
      } else if (kind === 'hex') {
        out = s.replace(/^0x/i, '').replace(/[^0-9a-f]/gi, '').match(/.{2}/g).map(h => String.fromCharCode(parseInt(h, 16))).join('');
      } else if (kind === 'url') {
        out = decodeURIComponent(s);
      } else if (kind === 'unicode-escape') {
        out = s.replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
      }
      if (!out || out.length > LIMITS.MAX_DECODE_EXPANSION) return null;
      // Printable-ratio check: random bytes are not a hidden message.
      const printable = (out.match(/[\x20-\x7E\s]/g) || []).length / out.length;
      return printable > 0.85 ? out : null;
    } catch (_) { return null; }
  };

  const candidates = [];
  for (const m of [...text.matchAll(/\b[A-Za-z0-9+/]{24,4000}={0,2}\b/g)].slice(0, LIMITS.MAX_DECODE_CANDIDATES)) {
    if (m[0].length % 4 === 0) candidates.push({ kind: 'base64', raw: m[0], offset: m.index });
  }
  for (const m of [...text.matchAll(/\b(?:0x)?[0-9a-f]{40,4000}\b/gi)].slice(0, 10)) {
    candidates.push({ kind: 'hex', raw: m[0], offset: m.index });
  }
  for (const m of [...text.matchAll(/(?:%[0-9a-f]{2}){6,}/gi)].slice(0, 10)) {
    candidates.push({ kind: 'url', raw: m[0], offset: m.index });
  }
  for (const m of [...text.matchAll(/(?:\\u[0-9a-f]{4}){4,}/gi)].slice(0, 10)) {
    candidates.push({ kind: 'unicode-escape', raw: m[0], offset: m.index });
  }

  for (const c of candidates) {
    const decoded = tryDecode(c.raw, c.kind);
    if (!decoded) continue;
    const inner = runRules(decoded);
    const innerUrls = analyseUrls(decoded);
    const worst = [...inner, ...innerUrls.findings]
      .filter(f => SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER.MEDIUM);

    artifacts.push({ kind: c.kind, offset: c.offset, length: c.raw.length, decodedPreview: decoded.slice(0, 200), revealed: worst.length });

    if (worst.length) {
      findings.push(makeFinding({
        ruleId: 'ENCODED_PAYLOAD_001', category: 'ENCODED_PAYLOAD', severity: 'HIGH', confidence: 0.88,
        title: `Hidden instructions found inside ${c.kind} text`,
        plain: `A scrambled-looking block in this prompt decodes to readable instructions. Concealing the instruction is the point — a prompt with nothing to hide does not need encoding.`,
        technical: `${c.kind} blob at offset ${c.offset} (${c.raw.length} chars) decoded to content matching: ${worst.map(f => f.ruleId).join(', ')}. Decoded, never executed.`,
        evidence: { excerpt: decoded.slice(0, 180).replace(/\s+/g, ' '), start: c.offset, end: c.offset + c.raw.length, fromNormalized: true },
        action: 'Do not use this prompt. Read the decoded text above — that is what it actually says.',
        source: 'decoder',
      }));
    } else if (decoded.length > 40 && /\s/.test(decoded)) {
      findings.push(makeFinding({
        ruleId: 'ENCODED_PAYLOAD_002', category: 'ENCODED_PAYLOAD', severity: 'LOW', confidence: 0.55,
        title: `Encoded text present (${c.kind})`,
        plain: 'Part of this prompt is encoded. It decoded to ordinary text with nothing alarming in it. Encoding by itself is not evidence of anything.',
        technical: `${c.kind} blob at offset ${c.offset}; decoded cleanly, no rule matches.`,
        evidence: { excerpt: decoded.slice(0, 180).replace(/\s+/g, ' '), start: c.offset, end: c.offset + c.raw.length, fromNormalized: true },
        action: 'No action needed, but you can read the decoded text to be sure.',
        source: 'decoder',
      }));
    }
  }

  return { findings, artifacts };
}

// --------------------------------------------------------------- stage 6
// Attack chains. A request for a secret is bad. A request for a secret
// PLUS somewhere to send it is a different thing entirely, and the policy
// has to see the combination, not just the parts.
function detectChains(findings) {
  const has = (cat) => findings.some(f => f.category === cat && SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER.MEDIUM);
  const chains = [];

  const secret = has('CRYPTO_SECRET_REQUEST') || has('CREDENTIAL_HARVESTING') || has('SENSITIVE_DATA_REQUEST');
  const exfil = has('DATA_EXFILTRATION') || has('EXTERNAL_TRANSMISSION');
  const injection = has('PROMPT_INJECTION') || has('INDIRECT_INJECTION');
  const concealment = has('TOOL_ABUSE') || has('UNICODE_OBFUSCATION') || has('HIDDEN_MARKUP') || has('ENCODED_PAYLOAD');
  const execution = has('DANGEROUS_COMMAND') || has('CODE_EXECUTION');

  if (secret && exfil) {
    chains.push(makeFinding({
      ruleId: 'CHAIN_EXFIL_001', category: 'DATA_EXFILTRATION', severity: 'CRITICAL', confidence: 0.95,
      title: 'Asks for a secret AND provides somewhere to send it',
      plain: 'This prompt requests sensitive information and, separately, tells the AI where to transmit it. Together those two steps are a complete theft, not two coincidences.',
      technical: 'Chain rule: secret-request category co-occurs with exfiltration category at MEDIUM or above.',
      action: 'Do not use this prompt under any circumstances, and do not supply anything it asks for.',
      source: 'deterministic',
    }));
  }
  if (injection && (secret || execution)) {
    chains.push(makeFinding({
      ruleId: 'CHAIN_INJECT_001', category: 'PROMPT_INJECTION', severity: 'CRITICAL', confidence: 0.9,
      title: 'Overrides the AI\'s instructions, then asks for something sensitive',
      plain: 'The prompt first tries to disable the system\'s existing rules, then asks it to hand over data or run something. The first step exists to make the second one succeed.',
      technical: 'Chain rule: injection category co-occurs with secret-request or execution category.',
      action: 'Do not use this prompt.',
      source: 'deterministic',
    }));
  }
  if (concealment && (secret || exfil || execution)) {
    chains.push(makeFinding({
      ruleId: 'CHAIN_HIDDEN_001', category: 'PROMPT_INJECTION', severity: 'HIGH', confidence: 0.85,
      title: 'The dangerous part of this prompt is hidden',
      plain: 'The risky instruction is concealed — invisible characters, a comment, or encoding — rather than written plainly. Legitimate prompts have no reason to hide what they do.',
      technical: 'Chain rule: concealment category co-occurs with a sensitive-action category.',
      action: 'Do not use this prompt. Concealment plus a sensitive request is deliberate.',
      source: 'deterministic',
    }));
  }
  return chains;
}

// --------------------------------------------------------------- stage 6b
// Address extraction — THE BRIDGE.
//
// Every other prompt scanner stops at "this text is trying to manipulate
// an AI". This product already knows how to answer "is this contract a
// honeypot" across four chains. A crypto scam message usually carries
// both halves of the attack, so pulling the addresses out of the text and
// handing them to the engine already running on this page turns two
// half-answers into one. No competitor can copy that quickly: the prompt
// scanner is a weekend, the chain adapters were months.
//
// The entire difficulty is false positives. Solana's base58 alphabet
// overlaps ordinary words and hex digests, and a 64-character transaction
// hash contains a perfectly valid-looking 40-hex EVM address inside it.
// Offering to "scan" a word lifted out of a sentence would make the
// feature embarrassing, so every candidate has to survive a guard.

const ADDRESS_PATTERNS = [
  // Sui first: it starts with 0x and would otherwise be eaten by the EVM
  // pattern. Most specific wins.
  { chain: 'sui', re: /(?<![0-9a-zA-Z])0x[0-9a-fA-F]{1,64}::[A-Za-z_]\w{0,40}::[A-Za-z_]\w{0,40}/g },
  // EVM: 0x + exactly 40 hex. The trailing guard is what stops a 64-hex
  // transaction hash from yielding a bogus address out of its prefix.
  { chain: 'evm', re: /(?<![0-9a-zA-Z])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])/g },
  // TRON: T + 33 base58 characters, 34 total.
  { chain: 'tron', re: /(?<![0-9a-zA-Z])T[1-9A-HJ-NP-Za-km-z]{33}(?![0-9a-zA-Z])/g },
  // Solana: base58, 32-44. Guarded hard below.
  { chain: 'solana', re: /(?<![0-9a-zA-Z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![0-9a-zA-Z])/g },
];

function looksLikeSolanaAddress(s) {
  // A real base58 key is dense noise: digits, upper and lower all present.
  // Long words, hex digests and base64 fragments each fail at least one.
  if (!/[0-9]/.test(s)) return false;           // no digits -> a word, not a key
  if (!/[A-Z]/.test(s)) return false;
  if (!/[a-z]/.test(s)) return false;
  if (/^[0-9a-fA-F]+$/.test(s)) return false;   // pure hex -> a hash
  if (/[0OIl]/.test(s)) return false;           // not in the base58 alphabet at all
  if (/[a-z]{12,}/.test(s) || /[A-Z]{12,}/.test(s)) return false; // reads as text
  // Bitcoin legacy addresses are base58 too — P2PKH starts with 1, P2SH
  // with 3, both 26-35 characters — and they sail past every test above.
  // A Solana pubkey is 32 bytes, which lands at 43-44 base58 characters in
  // practice, so a short candidate with a Bitcoin prefix is a Bitcoin
  // address. Offering a Solana scan on one would be worse than silence.
  if (/^[13]/.test(s) && s.length <= 35) return false;
  return true;
}

// KNOWN GAPS in address extraction, recorded so they stay choices rather
// than surprises: Bitcoin (excluded above — there is no adapter for it),
// bech32 addresses such as bc1… (excluded by the base58 alphabet itself),
// Cosmos-family chains, Cardano, and ENS names like vitalik.eth, which do
// resolve to an address but only through a lookup this page never makes.

function extractAddresses(text) {
  const found = [];
  const claimed = [];
  const overlaps = (a, b) => claimed.some(r => a < r.end && b > r.start);

  for (const { chain, re } of ADDRESS_PATTERNS) {
    re.lastIndex = 0;
    let m, guard = 0;
    while ((m = re.exec(text)) !== null && guard++ < 400) {
      const addr = m[0];
      const start = m.index, end = start + addr.length;
      if (overlaps(start, end)) continue;
      if (chain === 'solana' && !looksLikeSolanaAddress(addr)) continue;
      claimed.push({ start, end });
      found.push({ chain, address: addr, start, end });
      if (found.length >= 25) return found.sort((a, b) => a.start - b.start);
    }
  }
  return found.sort((a, b) => a.start - b.start);
}

// Reported as INFO on purpose. An address in a message is not itself a
// risk, and scoring it as one would punish every legitimate mention of a
// token. The value is the offer to check it, which the UI turns into
// buttons wired to the chain adapters already on the page.
function addressFindings(addresses) {
  if (!addresses.length) return [];
  const byChain = {};
  addresses.forEach(a => { byChain[a.chain] = (byChain[a.chain] || 0) + 1; });
  const summary = Object.entries(byChain).map(([c, n]) => `${n} ${c.toUpperCase()}`).join(', ');
  return [makeFinding({
    ruleId: 'ADDRESS_PRESENT_001',
    category: 'BENIGN_INFORMATIONAL',
    severity: 'INFO',
    confidence: 0.9,
    title: `${addresses.length} crypto address${addresses.length === 1 ? '' : 'es'} found in this text`,
    plain: 'A message pushing you to act on a token or wallet can be checked further. These addresses can go straight through the chain scanner without leaving this page.',
    technical: `Extracted: ${summary}. Candidates are filtered for base58 density and hex-digest collisions before being offered.`,
    evidence: {
      excerpt: addresses.slice(0, 3).map(a => `${a.chain}: ${a.address}`).join('\n'),
      start: addresses[0].start, end: addresses[0].end, fromNormalized: false,
    },
    action: 'Scan each address before sending anything to it, or approving anything for it.',
    source: 'deterministic',
  })];
}

// --------------------------------------------------------------- stage 7
// Policy. Deterministic, ordered, and testable. One critical finding
// outranks any number of clean signals; missing analysis never becomes
// PASS by silence.
function decideVerdict(findings, coverage, limitations) {
  const counted = findings.filter(f => SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER.LOW);
  const crit = counted.filter(f => f.severity === 'CRITICAL');
  const high = counted.filter(f => f.severity === 'HIGH');
  const med = counted.filter(f => f.severity === 'MEDIUM');
  const low = counted.filter(f => f.severity === 'LOW');

  const materialGap = limitations.some(l => l.material);

  let verdict, label, sub;
  if (crit.length) {
    verdict = 'fail'; label = 'FAIL';
    sub = 'A high-confidence dangerous pattern was found. Do not use this prompt or give it private information.';
    crit.forEach(f => { f.contributed = true; });
    high.forEach(f => { f.contributed = true; });
  } else if (high.length >= 2) {
    verdict = 'fail'; label = 'FAIL';
    sub = 'Several serious warning signs together form a coherent attack pattern.';
    high.forEach(f => { f.contributed = true; });
  } else if (materialGap) {
    verdict = 'unknown'; label = 'INSUFFICIENT DATA';
    sub = 'Enough of this prompt could not be analysed to give you a reliable answer. This is not a clean result.';
  } else if (high.length === 1 || med.length) {
    verdict = 'caution'; label = 'CAUTION';
    sub = 'This prompt contains warning signs that deserve review before you use it.';
    high.forEach(f => { f.contributed = true; });
    med.forEach(f => { f.contributed = true; });
  } else if (low.length) {
    verdict = 'caution'; label = 'CAUTION';
    sub = 'Minor concerns found. Worth a look, but nothing high-risk was detected.';
    low.forEach(f => { f.contributed = true; });
  } else {
    verdict = 'pass'; label = 'PASS';
    sub = 'No covered high-risk pattern was detected. This is not a guarantee that the prompt is safe in every context.';
  }

  const confidence = crit.length ? 'high'
    : materialGap ? 'low'
    : (high.length || med.length) ? 'medium'
    : 'high';

  return {
    verdict, label, sub, confidence,
    counts: { critical: crit.length, high: high.length, medium: med.length, low: low.length, informational: findings.length - counted.length },
  };
}

// ----------------------------------------------------------------- entry
function scanPrompt(input, opts) {
  const options = Object.assign({ decode: true, analyzeUrls: true }, opts || {});
  const started = Date.now();
  const limitations = [];

  if (typeof input !== 'string') {
    return {
      verdict: 'unknown', label: 'INSUFFICIENT DATA',
      sub: 'Nothing readable was submitted.',
      findings: [], urls: [], decoded: [], addresses: [],
      coverage: { unicode: 'unavailable', markup: 'unavailable', encoding: 'unavailable', urls: 'unavailable', semantic: 'unavailable', reputation: 'not_checked' },
      limitations: [{ text: 'Input was not text.', material: true }],
      input: { characters: 0, truncated: false },
      scannerVersion: SCANNER_VERSION,
    };
  }

  let text = input;
  let truncated = false;
  if (text.length > LIMITS.MAX_INPUT_CHARS) {
    text = text.slice(0, LIMITS.MAX_INPUT_CHARS);
    truncated = true;
    limitations.push({ text: `Only the first ${LIMITS.MAX_INPUT_CHARS.toLocaleString()} characters were analysed. The rest was not examined and could contain anything.`, material: true });
  }

  if (!text.trim()) {
    return {
      verdict: 'unknown', label: 'INSUFFICIENT DATA',
      sub: 'Nothing to analyse — the prompt was empty.',
      findings: [], urls: [], decoded: [], addresses: [],
      coverage: { unicode: 'unavailable', markup: 'unavailable', encoding: 'unavailable', urls: 'unavailable', semantic: 'unavailable', reputation: 'not_checked' },
      limitations: [{ text: 'No text was submitted.', material: true }],
      input: { characters: 0, truncated: false },
      scannerVersion: SCANNER_VERSION,
    };
  }

  const findings = [];
  const coverage = { unicode: 'complete', markup: 'complete', encoding: 'complete', urls: 'complete', semantic: 'unavailable', reputation: 'not_checked' };

  // Unicode
  const uni = analyseUnicode(text);
  findings.push(...uni.findings);

  // Markup — on the visible text, so hidden characters cannot break the parser.
  const mk = analyseMarkup(uni.visible);
  findings.push(...mk.findings);
  if (!mk.looksLikeMarkup) coverage.markup = 'not_applicable';

  // Rules run over BOTH the original and the invisible-stripped text: an
  // instruction split by zero-width characters is invisible to a regex
  // over the raw string but obvious once they are removed.
  const seen = new Set();
  for (const f of runRules(text)) { seen.add(f.ruleId); findings.push(f); }
  if (uni.changed) {
    for (const f of runRules(uni.visible)) {
      if (!seen.has(f.ruleId)) {
        f.technical += ' Detected only after removing invisible characters — the raw text was obfuscated to evade exactly this check.';
        f.evidence.fromNormalized = true;
        findings.push(f);
      }
    }
  }

  // URLs
  let urls = [];
  if (options.analyzeUrls) {
    const ua = analyseUrls(uni.visible);
    findings.push(...ua.findings);
    urls = ua.urls;
    if (!urls.length) coverage.urls = 'not_found';
  } else {
    coverage.urls = 'unavailable';
    limitations.push({ text: 'Link analysis was switched off for this scan.', material: true });
  }

  // Encoded payloads
  let decoded = [];
  if (options.decode) {
    const enc = analyseEncoding(uni.visible);
    findings.push(...enc.findings);
    decoded = enc.artifacts;
  } else {
    coverage.encoding = 'unavailable';
    limitations.push({ text: 'Encoded-content analysis was switched off for this scan.', material: true });
  }

  // Addresses — the bridge to the chain scanner.
  const addresses = extractAddresses(uni.visible);
  findings.push(...addressFindings(addresses));

  // Chains
  findings.push(...detectChains(findings));

  // Standing limitations — always shown, never dismissed.
  limitations.push(
    { text: 'This scan never ran the prompt. It reads it the way a spell-checker does.', material: false },
    { text: 'Links were inspected by their structure only. No address in the prompt was visited, and no reputation service was consulted.', material: false },
    { text: 'A prompt that looks harmless on its own can still be dangerous once an AI system has your files, your browser, a wallet, or the ability to act.', material: false },
    { text: 'Meaning-level analysis is not part of this scan. Detection is pattern-based, so a technique written in an unusual way may pass unnoticed.', material: false },
  );

  const decision = decideVerdict(findings, coverage, limitations);

  findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || b.confidence - a.confidence);

  return {
    verdict: decision.verdict,
    label: decision.label,
    sub: decision.sub,
    confidence: decision.confidence,
    counts: decision.counts,
    findings,
    urls,
    decoded,
    addresses,
    coverage,
    limitations,
    input: {
      characters: input.length,
      analysed: text.length,
      truncated,
      invisibleCharactersRemoved: uni.strippedCount,
      normalizedDiffers: uni.changed,
    },
    elapsedMs: Date.now() - started,
    scannerVersion: SCANNER_VERSION,
  };
}

const SCANNER_VERSION = '0.1.0';

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    scanPrompt, analyseUnicode, analyseMarkup, analyseUrls, analyseEncoding,
    runRules, detectChains, decideVerdict, directiveScore, registrable, sameSite,
    extractAddresses, addressFindings, looksLikeSolanaAddress,
    RULES, LIMITS, SEVERITY_ORDER, SCANNER_VERSION,
  };
}
