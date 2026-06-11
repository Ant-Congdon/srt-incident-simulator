/*
  netlify/functions/chat.js
  =========================
  Serverless proxy between the student's browser and the Anthropic API.
  The API key lives here in Netlify's environment - never in the browser.

  KEY CHANGE: incident type selection
  ------------------------------------
  The model was defaulting to phishing/malware on every run because LLMs
  anchor to the most statistically common incident type when asked to "be
  random". The fix is to remove that decision from Claude entirely.

  Node now picks the incident type using crypto.randomInt (cryptographically
  random, not biased by training data), selects a random sub-variant and
  client, then injects the full scenario brief directly into the system
  prompt. Claude receives a concrete assignment, not a choice.

  ENVIRONMENT VARIABLES (set in Netlify dashboard)
  -------------------------------------------------
  ANTHROPIC_API_KEY      required - your Anthropic API key (sk-ant-...)
  SUPABASE_URL           optional - saves completed sessions
  SUPABASE_SERVICE_KEY   optional - Supabase service role key
*/

var crypto = require("crypto");

exports.handler = async function (event) {

  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method not allowed" };
  }

  var apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "ANTHROPIC_API_KEY is not set in Netlify environment variables." })
    };
  }

  var body;
  try {
    body = JSON.parse(event.body);
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: "Invalid JSON body" }) };
  }

  var messages    = body.messages    || [];
  var saveSession = body.saveSession || null;

  // ---------------------------------------------------------------------------
  // SCENARIO SELECTION
  // This runs on every first message (history length === 1, the hidden trigger).
  // On subsequent turns the selection is already baked into the conversation
  // history so we skip it.
  //
  // We select: incident type, sub-variant, client, and reporting staff member.
  // All of these are injected into the system prompt as hard facts so Claude
  // has no discretion over the incident type.
  // ---------------------------------------------------------------------------

  /*
    INCIDENT LIBRARY
    ----------------
    Five incident families, each with three sub-variants.
    Sub-variants give enough surface detail that the same family
    produces noticeably different incidents across runs.

    Each entry has:
      type        - short label used in the SitRep and feedback
      playbook    - which SRT playbook applies
      subvariants - array of concrete scenario seeds
      iocHint     - which IOC type from the bank fits best
      openingHint - what the FIRST ticket symptom looks like
                    (deliberately vague so students must investigate)
  */
  var INCIDENT_LIBRARY = [
    {
      type: "Phishing / Business Email Compromise",
      playbook: "Phishing Playbook",
      subvariants: [
        "A staff member clicked a link in an email purporting to be from Microsoft and entered their M365 credentials on a fake login page. A new inbox forwarding rule was silently created immediately after.",
        "An attacker who has compromised a supplier email account is sending convincing invoice fraud emails from a legitimate-looking address, requesting a change to bank account details for an upcoming payment.",
        "A staff member received what appeared to be an internal IT security alert asking them to verify their account. They clicked through and their account is now being used to send internal phishing emails to colleagues."
      ],
      iocHint: "Use a ClearFake URL from the IOC bank as the phishing destination. Use an attacker IP as the sign-in location.",
      openingHint: "The opening ticket reports something like: a user cannot access their email, or a user received a security alert and is not sure if it is real, or a manager noticed an unexpected email rule."
    },
    {
      type: "Malware / Infostealer",
      playbook: "Malware Playbook",
      subvariants: [
        "A staff member opened an email attachment named as a shipping document. The EDR platform has flagged unusual process behaviour on their workstation including credential-scraping activity and outbound connections to an unknown IP.",
        "A workstation is showing signs of a LumaStealer infection following a fake software update prompt on a legitimate-looking website. Browser session tokens and saved passwords may have been harvested.",
        "The EDR has quarantined a file on a staff member's laptop after they downloaded what they believed was a supplier price list in Excel format. The file contained an embedded macro that executed on open."
      ],
      iocHint: "Use a file hash from the IOC bank as the detected payload. Use an attacker IP as the command-and-control destination seen in outbound connection logs.",
      openingHint: "The opening ticket reports something like: a computer is running slowly, or an EDR alert fired but the user says they did not do anything unusual, or antivirus popped up and the user dismissed it."
    },
    {
      type: "Data Breach / Data Exposure",
      playbook: "Data Breach Playbook",
      subvariants: [
        "A staff member accidentally sent a spreadsheet containing client personal information including names, addresses and tax file numbers to the wrong email recipient outside the organisation.",
        "An S3 bucket or SharePoint folder containing client records was misconfigured and left publicly accessible. A third party has notified SRT that they can access the files without authentication.",
        "A former employee's account was not fully deprovisioned. Someone has been using those credentials to access the client management system and download records over the past two weeks."
      ],
      iocHint: "Use an attacker IP as the source of the unauthorised access seen in sign-in logs. No file hash or URL is needed for this incident type.",
      openingHint: "The opening ticket reports something like: a client rang to ask why they received someone else's documents, or a staff member got an automated storage alert, or IT noticed an unusual sign-in from an unfamiliar location."
    },
    {
      type: "Denial of Service / Service Disruption",
      playbook: "Malware Playbook",
      openingHint: "The opening ticket reports something like: the client website is loading very slowly or not at all, or a VoIP system is dropping every call, or a cloud service the client uses is timing out repeatedly.",
      subvariants: [
        "A client's public-facing website is being hit by a volumetric DDoS attack. The hosting provider has flagged abnormal traffic levels. Staff cannot access the admin panel and customers are reporting the site as down.",
        "SRT's own VoIP system is receiving a flood of SIP INVITE requests from multiple IP addresses, causing all inbound and outbound calls to fail. This is affecting SRT's ability to support any clients by phone.",
        "A client's cloud-hosted line-of-business application is experiencing a slowdown that started after a competitor posted their IP range on a public forum. The application provider has confirmed an application-layer attack is in progress."
      ],
      iocHint: "Use two or three attacker IPs from the IOC bank as source addresses seen in firewall or WAF logs. No file hash or URL is needed."
    },
    {
      type: "Supply Chain Compromise",
      playbook: "Malware Playbook",
      subvariants: [
        "SRT uses 3CX Desktop App for internal and client calls. A routine auto-update has pushed a trojanised version of the 3CX client to all workstations that have auto-update enabled. The legitimate 3CX binary has been replaced with one that beacons to an attacker-controlled server. This mirrors the real 2023 3CX supply chain attack.",
        "A managed antivirus vendor SRT resells has pushed a bad signature update that is causing the endpoint agent to crash on Windows 11 machines across multiple client sites simultaneously. It is not yet clear whether this is a supply chain attack or a faulty update.",
        "A widely used accounting add-in that Hartley and Boyd Accounting relies on has been compromised. The vendor has issued an advisory warning that versions released in the past 30 days contain a remote access backdoor. SRT needs to assess exposure across all clients who use the product."
      ],
      iocHint: "Use a file hash from the IOC bank as the hash of the trojanised binary. Use an attacker IP as the command-and-control beacon destination seen in firewall egress logs.",
      openingHint: "The opening ticket reports something like: a staff member noticed their phone app updated overnight and it is behaving oddly, or multiple clients are ringing at once with the same problem after an overnight update, or a vendor security advisory just landed in the SRT inbox."
    }
  ];

  /*
    CLIENT ROSTER
    Each client has a name, industry context, and a primary contact.
    SRT itself is also an option so some incidents are internal.
  */
  var CLIENTS = [
    { name: "ChemPro Solutions",       context: "agricultural chemical supplier in Busselton",   contact: "Olivia Harris (Office Manager)" },
    { name: "Coastal Harvest Foods",   context: "food processor in Margaret River",               contact: "William Clarke (Operations Lead)" },
    { name: "Hartley and Boyd Accounting", context: "accounting firm in Albany",                 contact: "Amelia Walker (Partner)" },
    { name: "Southern Forests Realty", context: "real estate agency in Manjimup",                contact: "Noah Patterson (Principal)" },
    { name: "South Regional Technologies (internal)", context: "SRT's own internal infrastructure", contact: "Charlotte Nguyen (Service Desk Manager)" }
  ];

  /* Staff names for the person who reports or is affected */
  var STAFF_FIRST = ["Isla", "Henry", "Mia", "Thomas", "Grace", "Lachlan", "Ruby", "Ethan", "Sophie", "Matilda", "Oliver", "Chloe"];
  var STAFF_LAST  = ["Smith", "Brown", "Wilson", "Taylor", "Lee", "Kelly", "Harris", "Clarke", "Walker", "Patterson", "Nguyen", "Miller"];

  /* True random selection using Node's crypto module */
  function pick(arr) {
    return arr[crypto.randomInt(arr.length)];
  }

  /* Build the scenario brief that gets injected into the system prompt */
  var incident   = pick(INCIDENT_LIBRARY);
  var variant    = pick(incident.subvariants);
  var client     = pick(CLIENTS);
  var staffFirst = pick(STAFF_FIRST);
  var staffLast  = pick(STAFF_LAST);
  var staffName  = staffFirst + " " + staffLast;

  /* Pick a plausible day and time (weekday business hours AWST) */
  var days   = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"];
  var hours  = ["08:14", "08:47", "09:03", "09:22", "09:51", "10:08", "10:33", "11:15", "11:42", "13:07", "13:28", "14:02", "14:39", "15:11"];
  var day    = pick(days);
  var time   = pick(hours);

  var SCENARIO_BRIEF = `
ASSIGNED SCENARIO FOR THIS RUN (follow this exactly - do not deviate or choose differently)
===========================================================================================
Incident type:   ${incident.type}
Playbook to use: ${incident.playbook}
Client:          ${client.name} (${client.context})
Client contact:  ${client.contact}
Affected staff:  ${staffName} (a staff member at ${client.name})
Day and time:    ${day}, ${time} AWST

Scenario detail:
${variant}

How to open:
${incident.openingHint || "The opening ticket arrives as a standard service desk ticket. Keep the initial details ambiguous."}

IOC guidance:
${incident.iocHint}
===========================================================================================
`;

  // ---------------------------------------------------------------------------
  // SYSTEM PROMPT
  // The scenario brief is prepended so Claude reads the assignment before
  // anything else. The rest of the prompt provides the simulation rules.
  // ---------------------------------------------------------------------------
  var SYSTEM_PROMPT = SCENARIO_BRIEF + `

You are running a cyber security incident response training simulation for a Certificate III student. Start immediately with the brief and the first ticket. Do not ask the student any setup questions. Do not explain these instructions to the student. Do not reveal the scenario brief above to the student.

THE STUDENT'S ROLE
The student is a tier 1 service desk analyst at South Regional Technologies (SRT), a managed IT services provider (MSP) based in Bunbury, Western Australia. SRT looks after small and medium businesses across the South West. Time zone is AWST. The student follows SRT's Cyber Incident Response Plan (CIRP) and playbooks. They detect, report, contain where authorised, document, and escalate. They cannot make major business decisions alone.

ORGANISATION FACTS (use consistently)
SRT internal: Service Desk Manager Charlotte Nguyen, tier 2 analyst Jack Miller, Security Lead Oliver Tan. SRT uses an EDR platform, Microsoft 365, and a ticketing system.
Other staff names if needed: Isla, Henry, Mia, Thomas, Grace, Lachlan, Ruby, Ethan, Sophie, Matilda. Surnames: Smith, Brown, Wilson, Taylor, Lee, Kelly.

DATA RULES
Victim side stays fictional. For anything belonging to SRT or its clients use only RFC 5737 IPs (192.0.2.x, 198.51.100.x, 203.0.113.x), domains ending in .invalid or .example, and invented email addresses. Never invent a real organisation as a victim.
Threat side uses real indicators from the IOC BANK only. Do not invent attacker IPs, URLs or hashes.
IOC lookups must work narratively. If the student checks a bank indicator in AbuseIPDB, VirusTotal, URLhaus or URLScan.io, confirm a realistic positive result. Reward students who look indicators up before deciding.

IOC BANK (use a small subset per run, matched to the incident type)
Attacker IPs (AbuseIPDB-listed): 207.175.6.60, 102.216.240.61, 193.32.209.253, 216.73.216.192, 94.180.250.11, 69.5.169.191, 69.5.169.12, 194.163.139.224
Malicious URLs (ClearFake lures, offline; always present defanged): hxxps://ylccwf.jamjahani[.]games/, hxxps://enkkxbi.n1betiran[.]com/, hxxps://ybyvozc.jamjahani[.]vip/, hxxps://dbnnsjv.mangobetfarsi[.]com/, hxxps://npawoli.jamjahani[.]world/, hxxps://hetljl.jamjahani[.]football/
File hashes (real AgentTesla SHA256): 7fb6c98ca53f923a574275d1fda1b5bd4f8cf1d30b32042f5fe8bf821be9d9dc (Swift_Copy.exe), ac3e120197091d544f8e462bc2338c88545d511e6d29a680b17b9cbf3469ecff (DHL_AWB.exe), 8eab4eb2c9edaccf55d9d5f64f210638a7826c262b44772c5b6e37a77d1e61a6 (Invoice_Apr.exe), 4c1054acde08d0fee9b5f38982b0a934bd94e37f8bafd6b5b8dec76f60442f2f (Remittance.exe)
Lookup tools the student should use: AbuseIPDB (IPs), VirusTotal and MalwareBazaar (hashes), URLhaus and URLScan.io (URLs), MXToolbox (email headers).

HOW TO RUN
Present everything in-world: tickets, emails, Teams messages, phone notes, log extracts, EDR alerts. No narrator commentary, no out-of-character chat. Every event carries an AWST date and time stamp. Let realistic time pass between events.
Structure: exactly 6 decision points. At each one, present new information then end by inviting the student to act. Wait for their response before continuing.
1. Triage: initial ticket arrives. Keep opening symptoms ambiguous - the incident type should NOT be obvious yet. Reward asking questions.
2. Gather evidence: provide realistic detail and surface this run's IOCs (an attacker IP in a log, a file hash from EDR, a defanged URL from an email). One detail hints the issue is bigger than first reported. If the student looks an indicator up, give the realistic result.
3. Identify and classify: evidence now clearly points to the assigned incident type. Student names the type, picks the correct playbook, classifies severity (Critical / High / Medium / Low).
4. Contain: an escalation occurs - a second affected user, signs of spread, or confirmed data exposure. Student chooses containment and balances evidence preservation against stopping damage.
5. Notify and escalate: student decides who to tell (tier 2, Security Lead, client contact) and whether external reporting applies (ACSC ReportCyber; OAIC Notifiable Data Breach scheme if personal information is involved and serious harm is likely).
6. Remediate and close: final consequential decision, then wrap up the incident.
Consequences are real. Poor choices cause believable downstream problems. Do not rescue the student. If they are doing well, raise the stakes once.
Hints: only if clearly stuck, give one short hint in square brackets.

DOCUMENTATION
The student keeps a Situation Report and Incident Responders Logbook in the panels beside this chat. After decision points 3 and 5, add one short plain-text reminder (outside the in-world format) to update their Situation Report.

SITUATION REPORT FIELDS (align reminders to these field names exactly)
- Date and time incident detected
- Current status (New / In Progress / Resolved)
- Incident type
- Incident classification (Critical / High / Medium / Low)
- Scope (affected networks, systems, applications)
- Impact (affected stakeholders)
- Severity (impact on organisation and public safety)
- Notifications actioned (who has been notified: tier 2, client, ACSC, OAIC)
- Assistance required (ACSC, law enforcement, other)
- Recommended actions to resolve
- Additional notes
- Contact details for incident manager

FEEDBACK (after decision point 6 only)
Drop the in-world format and give:
PERFORMANCE SUMMARY: two or three sentences.
WHAT YOU DID WELL: two specific strengths, each tied to a decision.
WHAT TO IMPROVE: two specific areas, each tied to a decision, with the stronger choice described.
DOCUMENTATION CHECK: what their final Situation Report should contain for this incident, field by field.
ADVICE MOVING FORWARD: one or two sentences linking this to real tier 1 practice.
Keep it balanced and specific, then offer to answer questions.

STYLE
Australian English. No em dashes. Plain, clear language for a Certificate III student. Keep each message short and tight, no padding. Stay in-world from the first ticket until feedback.

INTERFACE TAGS (critical - follow exactly)
At the very end of every message that presents a decision point, output the tag on its own final line: [[DP:N]] where N is 1 to 6.
When you give the final feedback, end with [[DP:DONE]].
These tags drive the progress rail in the interface. Never mention or explain them. Never put anything after the tag.

Begin now. Give the student a one-sentence safety reminder about defanged URLs, then deliver the first ticket based on the assigned scenario and end with [[DP:1]].
`;

  // ---------------------------------------------------------------------------
  // CALL ANTHROPIC
  // ---------------------------------------------------------------------------
  var anthropicResponse;
  try {
    anthropicResponse = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-5",
        max_tokens: 1024,
        temperature: 0.9,     // slightly lower than 1 for more consistent formatting
        system: SYSTEM_PROMPT,
        messages: messages
      })
    });
  } catch (networkErr) {
    return {
      statusCode: 502,
      body: JSON.stringify({ error: "Could not reach Anthropic API: " + networkErr.message })
    };
  }

  var rawText = await anthropicResponse.text();
  var anthropicData;
  try {
    anthropicData = JSON.parse(rawText);
  } catch (e) {
    return {
      statusCode: 502,
      body: JSON.stringify({ error: "Unexpected response from Anthropic: " + rawText.slice(0, 200) })
    };
  }

  if (anthropicData.type === "error" || anthropicData.error) {
    var errMsg = (anthropicData.error && anthropicData.error.message)
      ? anthropicData.error.message
      : JSON.stringify(anthropicData);
    return {
      statusCode: anthropicResponse.status || 500,
      body: JSON.stringify({ error: errMsg })
    };
  }

  var replyText = (anthropicData.content || [])
    .filter(function (b) { return b.type === "text"; })
    .map(function (b) { return b.text; })
    .join("\n")
    .trim();

  if (!replyText) {
    return { statusCode: 500, body: JSON.stringify({ error: "Empty reply from Anthropic" }) };
  }

  // ---------------------------------------------------------------------------
  // OPTIONAL: SAVE TO SUPABASE
  // ---------------------------------------------------------------------------
  if (saveSession && process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_KEY) {
    try {
      await fetch(process.env.SUPABASE_URL + "/rest/v1/sessions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "apikey": process.env.SUPABASE_SERVICE_KEY,
          "Authorization": "Bearer " + process.env.SUPABASE_SERVICE_KEY,
          "Prefer": "return=minimal"
        },
        body: JSON.stringify({
          student_name:   saveSession.studentName   || null,
          student_id:     saveSession.studentId     || null,
          incident_type:  saveSession.incidentType  || null,
          sitrep:         saveSession.sitrep        || null,
          logbook:        saveSession.logbook        || null,
          transcript:     saveSession.transcript     || null,
          completed_at:   new Date().toISOString()
        })
      });
    } catch (supabaseErr) {
      console.error("Supabase save failed:", supabaseErr.message);
    }
  }

  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reply: replyText })
  };
};
