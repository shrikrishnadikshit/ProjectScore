// Draft legal texts. Replace the [bracketed] placeholders and have a lawyer review them, then set
// LEGAL_DRAFT to false to remove the "draft" label from the public pages.
export const LEGAL_DRAFT = true
export const COMPANY = '[Company legal name]'
export const ADDRESS = '[Registered address]'
export const CONTACT = '[privacy@yourdomain]'
export const UPDATED = '[Date]'

export const TERMS = [
  ['The service', `ProjectScore is an online service operated by ${COMPANY} ("we") that rates the external security of organisations from publicly available information and helps customers manage third-party cyber risk. These terms apply to every organisation and person who uses it.`],
  ['Accounts', 'Accounts are created by invitation. You are responsible for keeping your password safe, for everything done under your account, and for making sure the people you invite are allowed to use the service on your organisation\'s behalf.'],
  ['Acceptable use', 'You will use ProjectScore only to assess your own organisation, your suppliers, partners, customers or acquisition targets, or organisations you have another legitimate business reason to assess. You will not use ratings to harass, defame or extort anyone, try to break or overload the service, resell it without our agreement, or use it from or for a country, organisation or person subject to sanctions.'],
  ['Active testing and code reviews', 'In-depth scans and source code reviews are run only for domains and code your organisation owns or is authorised to test. By starting one you confirm, and you are responsible for, that authorisation. We keep the authorisation record you give us.'],
  ['Ratings are opinions', 'Ratings, risk estimates, framework mappings and loss figures are opinions based on what can be observed from outside at a point in time. They are not a guarantee of security, a certification, a compliance assessment, legal, financial or insurance advice. Decisions you make with them are your own.'],
  ['Accuracy and disputes', 'Rated organisations can dispute findings and ask not to be scanned. We review disputes promptly and correct or remove findings that are wrong. See the methodology page for how ratings are made.'],
  ['Confidentiality', 'Your portfolio, questionnaires, certificates, policies and in-depth results are confidential to your organisation. We do not share them with other customers.'],
  ['Data protection', 'We process personal data as described in the privacy policy. Where we process personal data on your behalf, the data processing agreement applies.'],
  ['Fees', '[Fees, billing period, taxes and renewal terms.]'],
  ['Availability and changes', 'We aim for high availability but do not promise uninterrupted service. We may improve or change features; we will tell you in advance about changes that materially reduce the service.'],
  ['Liability', `[To the extent the law allows, ${COMPANY}'s total liability is limited to the fees paid in the 12 months before the claim, and neither party is liable for indirect or consequential loss.]`],
  ['Ending the service', 'You can stop using ProjectScore at any time. We may suspend accounts that break these terms. When an organisation leaves, we delete its data as described in the privacy policy.'],
  ['Governing law', '[Governing law and courts, e.g. the laws of India and the courts of (city).]'],
  ['Contact', `${COMPANY}, ${ADDRESS}. Email: ${CONTACT}.`],
]

export const PRIVACY = [
  ['Who we are', `${COMPANY} (${ADDRESS}) runs ProjectScore and is responsible for the personal data described here. Contact: ${CONTACT}.`],
  ['Data about our users', 'Name, work email, organisation, role, password (stored only as a salted scrypt hash), sign-in sessions, API key names and what you do in the service (for example companies added, questionnaires sent). We use this to provide the service, keep it secure and support you. Legal basis: the contract with your organisation and our legitimate interest in running a secure service.'],
  ['Data about rated organisations', 'We collect information that organisations publish to the internet: DNS records, certificates, web server responses, network services, public threat-intelligence and breach listings. This is information about systems, not about individuals. Where a public breach listing names a breached service we store only the listing\'s summary (date, number of accounts, kinds of data), never anyone\'s personal records.'],
  ['People invited by our customers', 'When a customer sends a vendor a questionnaire or a fix link, we store the contact\'s name and email address and their replies, on the customer\'s behalf.'],
  ['Source code', 'Code submitted for review is read by automated scanners and deleted as soon as the review finishes. Only the findings are kept, with secret values hidden.'],
  ['Cookies', 'We use one essential cookie to keep you signed in, and short-lived essential cookies during single sign-on. We do not use advertising or analytics cookies.'],
  ['Sharing', 'We use service providers to host the service and send email: [Render (hosting and database, region), Resend (email), Sentry (error reports, if enabled)]. They act on our instructions. We do not sell personal data.'],
  ['International transfers', '[Where data leaves the EEA, UK or India, we rely on adequacy decisions, the EU Standard Contractual Clauses, the UK addendum or other lawful mechanisms.]'],
  ['Retention', 'Account data is kept while the account is active and deleted or anonymised within [30] days of closure. Scan data is kept while any customer monitors the organisation and for [24] months afterwards for rating history.'],
  ['Your rights', 'You can download your data and delete your account from the Account page. Depending on where you live (for example under the GDPR, the UK GDPR, India\'s DPDP Act 2023 or the California CCPA), you may also have rights to correct, restrict or object to processing, and to complain to a regulator. Email us to use them; we reply within one month.'],
  ['Opting out of scanning', 'Domain owners can ask us to stop scanning their domain on the scanner information page.'],
  ['Changes', 'We will post changes here and tell customers about significant ones.'],
]

export const DPA = [
  ['Scope', `This agreement applies when ${COMPANY} ("processor") processes personal data on behalf of a customer ("controller") through ProjectScore, for example user accounts and vendor contacts the customer adds. It forms part of the terms of service.`],
  ['Instructions', 'The processor processes personal data only on the controller\'s documented instructions, including these terms and the controller\'s use of the service, unless the law requires otherwise.'],
  ['Confidentiality', 'People authorised to process the data are bound by confidentiality.'],
  ['Security', 'The processor keeps appropriate technical and organisational measures (GDPR Art. 32), including encryption in transit, hashed passwords, access control by organisation, security headers, protection against server-side request forgery, error monitoring and backups. [Attach the current security measures annex.]'],
  ['Sub-processors', 'The controller authorises the sub-processors listed in the privacy policy. The processor will give notice of new sub-processors and the controller may object.'],
  ['Assistance', 'The processor helps the controller answer data-subject requests, carry out impact assessments and meet breach-notification duties.'],
  ['Breaches', 'The processor notifies the controller without undue delay, and in any case within [48] hours, after becoming aware of a personal data breach.'],
  ['International transfers', '[Standard Contractual Clauses (EU 2021/914, module 2 or 3), UK addendum and other transfer mechanisms as needed.]'],
  ['Deletion', 'At the end of the service the processor deletes or returns the personal data within [30] days, unless the law requires it to be kept.'],
  ['Audits', 'The processor makes available the information needed to show compliance and allows reasonable audits [once a year, with 30 days\' notice].'],
]
