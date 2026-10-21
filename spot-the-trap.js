/* Spot the Trap — the only script on the challenge pages.

   It shows the explanation when asked, and shares the public link.
   It stores nothing, sends nothing, and reads only this page: no
   storage, no network request, no clipboard read, no keyboard
   shortcuts. The chosen answer lives in a variable and is gone on
   reload. challenge.test.js holds it to that. */
(function () {
  'use strict';
  var form = document.getElementById('stt-form');
  if (!form) return;
  var reveal = document.getElementById('stt-reveal');
  var need = document.getElementById('stt-need');
  var expl = document.getElementById('stt-explanation');
  var heading = document.getElementById('stt-expl-heading');
  var yours = document.getElementById('stt-your-choice');
  var message = document.getElementById('stt-message');
  var verdict = document.getElementById('stt-verdict');
  var shareSection = document.getElementById('stt-share-section');
  var revealed = false;

  function chosen() {
    var r = form.querySelector('input[name="stt-choice"]:checked');
    return r ? r.value : null;
  }

  // Copies the feedback for the chosen answer from the full list, which
  // is already in the page as text. Built with textContent only.
  // Green panel for the recommended step, red for any other. The verdict
  // is also in words, so colour is never the only signal.
  function showYours(key) {
    var src = expl.querySelector('li[data-key="' + key + '"]');
    yours.textContent = '';
    if (!src) return;
    var right = src.getAttribute('data-recommended') === 'true';
    if (verdict) {
      verdict.classList.remove(right ? 'is-wrong' : 'is-right');
      verdict.classList.add(right ? 'is-right' : 'is-wrong');
    }
    heading.textContent = right ? '\u2713 Safe choice' : '\u2717 Risky choice';
    var label = document.createElement('p');
    label.className = 'stt-yours-label';
    label.textContent = 'You chose ' + key + '.';
    var text = document.createElement('p');
    text.textContent = src.getAttribute('data-feedback');
    yours.appendChild(label);
    yours.appendChild(text);
    if (right) {
      var ok = document.createElement('p');
      ok.className = 'stt-yours-rec';
      ok.textContent = 'This is the recommended next step.';
      yours.appendChild(ok);
    } else {
      var keys = ['A', 'B', 'C', 'D'];
      for (var i = 0; i < keys.length; i++) {
        var best = expl.querySelector('li[data-key="' + keys[i] + '"][data-recommended="true"]');
        if (!best) continue;
        var rec = document.createElement('p');
        rec.className = 'stt-yours-rec';
        rec.textContent = 'Safer step: ' + keys[i] + '. ' + best.getAttribute('data-choice') + ' ' + best.getAttribute('data-feedback');
        yours.appendChild(rec);
        break;
      }
    }
  }

  reveal.addEventListener('click', function () {
    var key = chosen();
    if (!key) {
      need.textContent = 'Choose an answer first.';
      return;
    }
    need.textContent = '';
    showYours(key);
    if (!revealed) {
      revealed = true;
      expl.hidden = false;
      if (shareSection) shareSection.hidden = false;
      if (message) {
        message.classList.add('revealed');
        var ns = message.querySelectorAll('.sign-n');
        for (var i = 0; i < ns.length; i++) ns[i].hidden = false;
      }
      reveal.textContent = 'Update the explanation';
    }
    // Focus moves to the explanation's heading; the explanation itself is
    // ordinary page text, read at the visitor's own pace.
    heading.focus();
  });

  // After the reveal, a new choice rewrites the feedback in place. Focus
  // stays on the radio button; a short polite status says what changed,
  // and the full feedback remains ordinary text to read on demand.
  var changeStatus = document.getElementById('stt-change-status');
  form.addEventListener('change', function () {
    need.textContent = '';
    if (!revealed) return;
    var key = chosen();
    showYours(key);
    if (changeStatus) {
      changeStatus.textContent = '';
      var rec = expl.querySelector('li[data-key="' + key + '"][data-recommended="true"]');
      changeStatus.textContent = 'Feedback updated for answer ' + key + (rec ? ', the recommended next step.' : '.');
    }
  });

  var share = document.getElementById('stt-share');
  var status = document.getElementById('stt-share-status');
  if (share) {
    share.addEventListener('click', function () {
      // Fixed words and the public address of this challenge. Never the
      // chosen answer.
      var url = share.getAttribute('data-url');
      var text = share.getAttribute('data-text');
      if (navigator.share) {
        navigator.share({ title: document.title, text: text, url: url }).catch(function () {});
        return;
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text + ' ' + url).then(function () {
          status.textContent = 'Link copied.';
        }, function () {
          status.textContent = 'Copy this link: ' + url;
        });
      } else {
        status.textContent = 'Copy this link: ' + url;
      }
    });
  }
})();
