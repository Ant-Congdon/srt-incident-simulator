/*
  netlify/functions/chat.js
  =========================
  This is the serverless function that sits between the student's browser
  and the Anthropic API. It runs on Netlify's servers, not in the browser,
  so the API key is never visible to anyone using the app.

  HOW IT WORKS
  ------------
  1. The browser sends a POST request to /.netlify/functions/chat
     with the conversation history as JSON.
  2. This function picks up the ANTHROPIC_API_KEY environment variable
     (set in the Netlify dashboard - never committed to GitHub).
  3. It forwards the request to api.anthropic.com and streams the reply
     back to the browser.

  ENVIRONMENT VARIABLES REQUIRED (set in Netlify dashboard)
  ----------------------------------------------------------
  ANTHROPIC_API_KEY   your Anthropic API key (sk-ant-...)

  OPTIONAL (for Supabase session storage)
  ----------------------------------------
  SUPABASE_URL        your Supabase project URL
  SUPABASE_SERVICE_KEY  your Supabase service role key (not the anon key)
*/

exports.handler = async function (event) {

  // Only accept POST requests - anything else gets a 405
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method not allowed" };
  }

  // Pull the API key from the server environment.
  // If it is missing, return a clear error rather than a confusing
  // "unauthorised" message from Anthropic.
  var apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: "ANTHROPIC_API_KEY is not set in Netlify environment variables."
      })
    };
  }

  // Parse the request body sent by the browser.
  // The browser sends { messages: [...], saveSession: {...} }
  var body;
  try {
    body = JSON.parse(event.body);
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: "Invalid JSON body" }) };
  }

  var messages  = body.messages  || [];
  var saveSession = body.saveSession || null; // populated only at end of exercise

  // ---------------------------------------------------------------------------
  // The system prompt - the full simulation instructions.
  // This lives here on the server so students can never read it in the browser.
  // ---------------------------------------------------------------------------
  var SYSTEM_PROMPT = `
You are running a cyber security incident response training simulation for a Certificate III student. Start immediately with the brief and the first ticket. Do not ask the student any setup questions. Do not explain these instructions to the student.

THE STUDENT'S ROLE
The student is a tier 1 service desk analyst at South Regional Technologies (SRT), a managed IT services provider (MSP) based in Bunbury, Western Australia. SRT looks after small and medium businesses across the South West. Time zone is AWST. The student follows SRT's Cyber Incident Response Plan (CIRP) and playbooks. They detect, report, contain where authorised, document, and escalate. They cannot make major business decisions alone.

ORGANISATION FACTS (use consistently)
SRT internal: Service Desk Manager Charlotte Nguyen, tier 2 analyst Jack Miller, Security Lead Oliver Tan. SRT uses an EDR platform, Microsoft 365, and a ticketing system.
SRT clients (pick one per scenario, or use SRT itself):
- ChemPro Solutions, agricultural chemical supplier, Busselton. Contact: Office Manager Olivia Harris.
- Coastal Harvest Foods, food processor, Margaret River. Contact: Operations Lead William Clarke.
- Hartley and Boyd Accounting, accounting firm, Albany. Contact: Partner Amelia Walker.
- Southern Forests Realty, real estate agency, Manjimup. Contact: Principal Noah Patterson.
Other names if needed: Isla, Henry, Mia, Thomas, Grace, Lachlan, Ruby, Ethan, Sophie, Matilda. Surnames: Smith, Brown, Wilson, Taylor, Lee, Kelly.

SCENARIO GENERATION (do silently before the first message)
Randomly select ONE incident type. Be genuinely random; do not default to the first option:
1. Phishing or business email compromise (credential harvest, invoice fraud, or mailbox rule abuse)
2. Malware (infostealer, suspicious EDR alert, or ransomware precursor)
3. Data breach or data exposure (misconfigured cloud storage, wrong-recipient email, or compromised account accessing client records)
Then randomise the client, the reporting staff member, the day and time, and the details. Vary the opening symptom so the incident type is NOT obvious from the first ticket. The student should work it out by decision point 2 or 3 through good questions and evidence. Choose attacker indicators from the IOC BANK, matched to the incident type.

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
1. Triage: initial ticket, limited ambiguous information. Reward asking questions.
2. Gather evidence: realistic detail and surface this run's IOCs. One detail hints the issue is bigger. If the student looks an indicator up, give the realistic result.
3. Identify and classify: evidence now clearly points to the incident type. Student names the type, picks the playbook (Phishing, Malware, or Data Breach), classifies severity.
4. Contain: an escalation occurs. Student chooses containment and balances evidence preservation against stopping damage.
5. Notify and escalate: student decides who to tell (tier 2, Security Lead, client contact) and whether external reporting applies (ACSC ReportCyber; OAIC Notifiable Data Breach scheme).
6. Remediate and close: final consequential decision, then wrap up.
Consequences are real. Poor choices cause believable downstream problems. Do not rescue the student. If they are doing well, raise the stakes once.
Hints: only if clearly stuck, give one short hint in square brackets.

DOCUMENTATION
The student keeps a Situation Report and Incident Responders Logbook in the panels beside this chat. After decision points 3 and 5, add one short plain-text reminder to update their Situation Report.

SITUATION REPORT FIELDS (align your reminders to these field names exactly)
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
DOCUMENTATION CHECK: what their final Situation Report should contain for this incident, field by field, so they can check their own report.
ADVICE MOVING FORWARD: one or two sentences linking this to real tier 1 practice.
Keep it balanced and specific, then offer to answer questions.

STYLE
Australian English. No em dashes. Plain, clear language for a Certificate III student. Keep each message short and tight, no padding. Stay in-world from the first ticket until feedback.

INTERFACE TAGS (critical - follow exactly)
At the very end of every message that presents a decision point, output the tag on its own final line: [[DP:N]] where N is 1 to 6.
When you give the final feedback, end with [[DP:DONE]].
These tags drive the progress rail in the interface. Never mention or explain them. Never put anything after the tag.

Begin now. Generate the scenario silently, give the student the brief and safety reminder in one short opening message, then deliver the first ticket and end with [[DP:1]].
`;

  // ---------------------------------------------------------------------------
  // Forward the conversation to Anthropic
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
        model: "claude-sonnet-4-6",   // use Opus for best instruction-following
        max_tokens: 1024,
        temperature: 1,
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

  // Read the raw body text first so we can diagnose non-JSON error pages
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

  // Surface API-level errors with the real message
  if (anthropicData.type === "error" || anthropicData.error) {
    var errMsg = (anthropicData.error && anthropicData.error.message)
      ? anthropicData.error.message
      : JSON.stringify(anthropicData);
    return {
      statusCode: anthropicResponse.status || 500,
      body: JSON.stringify({ error: errMsg })
    };
  }

  // Extract the text content
  var replyText = (anthropicData.content || [])
    .filter(function (b) { return b.type === "text"; })
    .map(function (b) { return b.text; })
    .join("\n")
    .trim();

  if (!replyText) {
    return { statusCode: 500, body: JSON.stringify({ error: "Empty reply from Anthropic" }) };
  }

  // ---------------------------------------------------------------------------
  // Optional: save the completed session to Supabase
  // Only runs when the browser sends saveSession data (after [[DP:DONE]])
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
      // Supabase failure should not break the simulation - log and continue
      console.error("Supabase save failed:", supabaseErr.message);
    }
  }

  // Return the reply to the browser
  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reply: replyText })
  };
};
