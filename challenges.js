/* =====================================================================
   SPOT THE TRAP — scenario content

   Build-time data only. build-challenges.js turns it into static pages,
   so every word a visitor reads is in the delivered HTML and can be
   reviewed in the repository. Nothing here runs in the browser.

   Copy is Stefan's revised draft of 20 October 2026, verbatim.

   Message text is a list of parts. A plain string is shown as written;
   { mark: n, text } is a detail the explanation numbers. Marks live in
   the text itself, not as character offsets, so editing or translating
   a message cannot silently move a highlight onto the wrong words.

   `reviewed` stays null until a person has approved the scenario's copy
   and its source. Source checking is not approval. `approvedHash`
   records exactly what was approved (contentHash in build-challenges.js).
   A release build (`node build-challenges.js --release`) refuses to run
   while any scenario is unreviewed or has changed since approval.
   ===================================================================== */

const CHALLENGES = [
  {
    id: 'deposit-job',
    version: 1,
    title: 'The job that asks for a deposit',
    channel: 'Chat',
    scene: 'An unexpected chat message offers online work. You decide to hear more. Later, after completing a set of tasks, the recruiter sends another message.',
    exchangeLabel: 'Invented exchange',
    messages: [
      { from: 'Recruiter', parts: [{ mark: 1, text: 'We have remote work rating product images.' }, ' Around 20 minutes a day. ', { mark: 2, text: 'You could earn $120–$300 daily.' }] },
      { from: 'Recruiter', parts: ['Your tasks are complete. ', { mark: 3, text: 'Your balance is now $486.' }] },
      { from: 'Recruiter', parts: ['Before you can withdraw, ', { mark: 4, text: 'deposit 49 USDT to activate Level 2' }, ". You'll get the deposit back with your payout. ", { mark: 5, text: 'Please finish today.' }] },
    ],
    choices: [
      { key: 'A', text: 'Pay the deposit and request the withdrawal.', feedback: 'The balance on the screen is a claim. Sending a deposit does not establish that those earnings exist or can be withdrawn.' },
      { key: 'B', text: 'Ask for a contract before deciding.', feedback: 'Asking questions is sensible, but a document supplied by the same person does not independently verify the offer.' },
      { key: 'C', text: 'Stop the payment and check the offer through company contact details I find independently.', recommended: true, feedback: 'Pause the payment. If you investigate further, use a contact route you find independently.' },
      { key: 'D', text: 'Send a smaller amount first.', feedback: 'A smaller payment is still money at risk. It does not verify the offer.' },
    ],
    detailsHeading: 'Details to notice',
    details: [
      'An unexpected job approach needs checking.',
      'The offer promises unusually large rewards for brief, repetitive work.',
      'The displayed balance is not proof of payment.',
      'A deposit is required to release the supposed earnings.',
      'The deadline discourages time to check.',
    ],
    note: null,
    remember: 'Do not send a deposit to unlock supposed wages or earnings.',
    source: {
      text: 'The FTC describes task scams involving repetitive online work, displayed earnings and demands for deposits, often in cryptocurrency.',
      label: 'FTC: Task scams create the illusion of making money',
      url: 'https://consumer.ftc.gov/consumer-alerts/2024/11/task-scams-create-illusion-making-money',
    },
    // Approved by Stefan on 21 October 2026 (content and source). The hash
    // is the wording approved; any material change needs a new review.
    reviewed: '2026-10-21',
    approvedHash: 'bee5a40cc68e95c9',
  },
  {
    id: 'safe-account',
    version: 1,
    title: 'The call about a “safe account”',
    channel: 'Text message',
    scene: "A caller says they work for your bank. Your phone displays the bank's name. During the call, this message arrives.",
    exchangeLabel: 'Invented message',
    messages: [
      { from: { mark: 4, text: 'Bank security' }, parts: ['We have detected suspicious access to your account. ', { mark: 1, text: 'Move your savings to the secure holding account discussed on the phone.' }, ' Use reference SAFE-4471. ', { mark: 3, text: 'Do this today.' }, ' ', { mark: 2, text: 'Do not speak to branch staff while the investigation is ongoing.' }] },
    ],
    choices: [
      { key: 'A', text: 'End the call, then contact the bank using its app or the number printed on my card.', recommended: true, feedback: "Break contact and check through the bank's established channel. Do not transfer money on this caller's instructions." },
      { key: 'B', text: 'Ask the caller to confirm more personal details.', feedback: 'Knowing personal information does not establish that someone represents your bank.' },
      { key: 'C', text: 'Transfer the money because the call and message appear to match.', feedback: 'Two messages from the same source do not provide independent confirmation.' },
    ],
    detailsHeading: 'Details to notice',
    details: [
      'The caller directs a transfer to supposedly protect your savings.',
      'The request discourages contact with other bank staff.',
      'The deadline adds pressure.',
      'A familiar-looking sender name does not establish who controls the conversation.',
    ],
    note: null,
    remember: 'A request to move money into a “safe account” is a reason to stop and contact your bank independently.',
    source: {
      text: 'The FTC describes fake fraud alerts that lead to callers pressuring people to move money to supposedly protect it.',
      label: 'FTC: Text scams that may target your business',
      url: 'https://www.ftc.gov/business-guidance/blog/2025/04/new-ftc-data-spotlight-highlights-text-scams-may-target-your-business',
    },
    // Approved by Stefan on 21 October 2026 (content and source). The hash
    // is the wording approved; any material change needs a new review.
    reviewed: '2026-10-21',
    approvedHash: '9809765d9db047e8',
  },
  {
    id: 'human-check',
    version: 1,
    title: 'The human check that asks you to run something',
    channel: 'Web page',
    scene: 'You follow a link to a document. Before it opens, a page displays these instructions.',
    exchangeLabel: 'Invented page — illustration only. Do not follow these steps.',
    // Shown as plain text only. The page copies nothing, reads nothing
    // and listens for no keyboard shortcut (challenge.test.js checks).
    messages: [
      { from: 'Verify you are human', parts: [{ mark: 1, text: 'Open Windows Run using Windows + R.' }, ' ', { mark: 2, text: 'Paste using Ctrl + V, then press Enter.' }] },
      { from: null, parts: ['Verification reference: 88412. ', { mark: 3, text: 'Complete this step to continue.' }] },
    ],
    choices: [
      { key: 'A', text: 'Follow the instructions to open the document.', feedback: 'The page is asking you to run something on your computer. A verification label does not make that action safe.' },
      { key: 'B', text: 'Repeat the instructions in another browser.', feedback: 'Changing browsers does not resolve the request to execute an unknown command.' },
      { key: 'C', text: 'Close the page and contact the person who sent the document through a channel I already trust.', recommended: true, feedback: 'Stop before running anything and check the request independently.' },
    ],
    detailsHeading: 'Details to notice',
    details: [
      'The instructions leave the website and open a system tool.',
      'They ask you to paste and execute content without explaining it.',
      'Access to the document depends on complying.',
    ],
    note: 'Some attacks copy a command during an earlier interaction. These instructions alone do not prove what is currently on your clipboard.',
    remember: 'Do not run a command to prove you are human.',
    source: {
      text: 'Microsoft documents ClickFix attacks that use apparent verification or troubleshooting instructions to get people to run malicious commands.',
      label: 'Microsoft: Think before you Click(Fix)',
      url: 'https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/',
    },
    // Approved by Stefan on 21 October 2026 (content and source). The hash
    // is the wording approved; any material change needs a new review.
    reviewed: '2026-10-21',
    approvedHash: '4e9b8f911420d57c',
  },
  {
    id: 'job-link',
    version: 1,
    title: 'The job offer with a link to sign in',
    channel: 'Email',
    scene: 'You have been applying for jobs online. An email arrives from a recruiter you do not recognise.',
    exchangeLabel: 'Invented message',
    // The address is written as plain text on a .example domain. The page
    // never makes it a link (challenge.test.js checks).
    messages: [
      { from: 'Talent team', parts: ['Congratulations! ', { mark: 1, text: 'You have been selected for a remote assistant role, no interview needed.' }, ' ', { mark: 2, text: 'To accept, sign in at hr-onboarding.example/start with your email address and email password.' }, ' ', { mark: 3, text: 'Then download and open the attached offer file.' }, ' ', { mark: 4, text: 'Add your bank card details so we can set up your first salary payment.' }, ' ', { mark: 5, text: 'This offer expires in 24 hours.' }] },
    ],
    choices: [
      { key: 'A', text: 'Follow the link and sign in to secure the job.', feedback: 'A sign-in page reached from an unexpected message can be a copy built to capture your password. A job offer does not make the link safe.' },
      { key: 'B', text: 'Open the attachment first to read the offer.', feedback: 'An attachment from a sender you have not verified can install malware. Opening it gives the sender what they want before you know who they are.' },
      { key: 'C', text: 'Reply and ask the recruiter whether the link is safe.', feedback: 'The sender cannot confirm their own link. Any reassurance comes from the same unverified source.' },
      { key: 'D', text: 'Leave the link and attachment alone, and check the role on the company website I find myself.', recommended: true, feedback: 'Check through a route you find yourself. A real employer will still have the role, or a way to reach the recruiter, there.' },
    ],
    detailsHeading: 'Details to notice',
    details: [
      'A job offered without an interview or any checking of you needs checking itself.',
      'The link asks for your email password, which no employer needs.',
      'An unexpected attachment can carry malware.',
      'Card details are requested before you have verified the employer.',
      'The short deadline discourages time to check.',
    ],
    note: null,
    remember: 'Do not click links, open attachments or share passwords or card details from a job offer until you have checked the employer yourself.',
    source: {
      text: 'The FTC explains how phishing messages use links and attachments to steal passwords and account details, and how to check a message through a source you trust.',
      label: 'FTC: How to recognize and avoid phishing scams',
      url: 'https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams',
    },
    // Approved by Stefan on 21 October 2026 (content and source). The hash
    // is the wording approved; any material change needs a new review.
    reviewed: '2026-10-21',
    approvedHash: 'd8527775840358ac',
  },
];

module.exports = { CHALLENGES };
