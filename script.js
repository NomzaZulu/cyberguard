/* ============================================================
   CYBERGUARD
   Organisation Security Platform

   Frontend:
   - Vanilla JavaScript
   - Hugging Face Gradio Client
   - No backend token exposed in browser

   Connected Space:
   saswatpatra/cyberguard_phishing

   Current API endpoints:
   /analyze_message
   /analyze_website
   /scan_qr
   ============================================================ */


/* ============================================================
   CONFIGURATION
   ============================================================ */

const CONFIG = {

    HF_SPACE:
        "saswatpatra/cyberguard_phishing",

    ENDPOINTS: {

        MESSAGE:
            "/analyze_message",

        WEBSITE:
            "/analyze_website",

        QR:
            "/scan_qr"
    },

    MAX_MESSAGE_LENGTH:
        15000,

    MAX_QR_SIZE:
        10 * 1024 * 1024,

    HISTORY_KEY:
        "cyberguard_analysis_history",

    ORGANISATION_KEY:
        "cyberguard_organisation",

    ORGANISATION_DOMAIN_KEY:
        "cyberguard_organisation_domain"
};


/* ============================================================
   GLOBAL STATE
   ============================================================ */

const state = {

    gradioClient: null,

    gradioHandleFile: null,

    clientLoading: false,

    currentView:
        "overview",

    currentAnalysis:
        "message",

    currentUrlMode:
        "url",

    selectedQrFile:
        null,

    takeoverEvents:
        null,

    takeoverProfiles:
        null,

    impersonationMessages:
        null,

    history:
        [],

    incidents:
        [],

    organisation:
        "Acme Corporation",

    organisationDomain:
        "acme-corp.com"
};


/* ============================================================
   DOM HELPERS
   ============================================================ */

function $(selector) {

    return document.querySelector(selector);
}


function $$(selector) {

    return document.querySelectorAll(selector);
}


/* ============================================================
   INITIALIZATION
   ============================================================ */

document.addEventListener(
    "DOMContentLoaded",
    initializeCyberGuard
);


async function initializeCyberGuard() {

    loadOrganisation();

    loadHistory();
    loadIncidents();

    initializeNavigation();

    initializeAnalysisTabs();

    initializeMessageInput();

    initializeUrlControls();

    initializeQrControls();

    initializeQuickActions();

    initializeAccountTakeover();

    initializeDigitalImpersonation();

    initializePdfExport();

    initializeRawToggles();

    initializeOrganisationSettings();

    initializeGlobalControls();

    updateOrganisationUI();

    await initializeGradioClient();
}


/* ============================================================
   GRADIO CLIENT
   ============================================================ */

async function initializeGradioClient() {

    if (state.gradioClient) {
        return state.gradioClient;
    }

    if (state.clientLoading) {
        return null;
    }

    state.clientLoading = true;

    try {

        /*
         * The @gradio/client package is loaded in index.html.
         * We dynamically import the same CDN package here so
         * script.js remains a normal JavaScript file.
         */

        const gradioModule = await import(
            "https://cdn.jsdelivr.net/npm/@gradio/client/dist/index.min.js"
        );

        const Client =
            gradioModule.Client;

        const handleFile =
            gradioModule.handle_file;

        if (!Client) {

            throw new Error(
                "Gradio Client could not be loaded."
            );
        }

        state.gradioHandleFile =
            handleFile;

        state.gradioClient =
            await Client.connect(
                CONFIG.HF_SPACE
            );

        console.log(
            "[CyberGuard] Connected to Hugging Face Space:",
            CONFIG.HF_SPACE
        );

        showToast(
            "Engine connected",
            "CyberGuard detection engine is ready.",
            "success"
        );

        return state.gradioClient;

    } catch (error) {

        console.error(
            "[CyberGuard] Gradio connection failed:",
            error
        );

        showToast(
            "Engine connection issue",
            "The interface loaded, but the Hugging Face engine could not be connected.",
            "error"
        );

        return null;

    } finally {

        state.clientLoading =
            false;
    }
}


/* ============================================================
   NAVIGATION
   ============================================================ */

function initializeNavigation() {

    $$(".nav-item").forEach(
        button => {

            button.addEventListener(
                "click",
                () => {

                    const view =
                        button.dataset.view;

                    if (!view) {
                        return;
                    }

                    navigateTo(view);
                }
            );
        }
    );


    $$("[data-view-target]").forEach(
        button => {

            button.addEventListener(
                "click",
                () => {

                    navigateTo(
                        button.dataset.viewTarget
                    );
                }
            );

            button.addEventListener(
                "keydown",
                event => {

                    if (event.key !== "Enter" && event.key !== " ") {
                        return;
                    }

                    event.preventDefault();

                    navigateTo(
                        button.dataset.viewTarget
                    );
                }
            );
        }
    );
}


function navigateTo(viewName) {

    const view =
        $(`#view-${viewName}`);

    if (!view) {
        return;
    }

    $$(".view").forEach(
        viewElement => {
            viewElement.classList.remove(
                "active"
            );
        }
    );

    view.classList.add("active");


    $$(".nav-item").forEach(
        item => {

            item.classList.toggle(
                "active",
                item.dataset.view === viewName
            );
        }
    );


    state.currentView =
        viewName;


    const names = {

        overview:
            "Security Overview",

        phishing:
            "Phishing Detection",

        takeover:
            "Account Takeover",

        impersonation:
            "Digital Impersonation",

        activity:
            "Analysis History",

        organisation:
            "Organisation"
    };


    const breadcrumb =
        $("#breadcrumbCurrent");

    if (breadcrumb) {

        breadcrumb.textContent =
            names[viewName] ||
            "CyberGuard";
    }


    closeMobileSidebar();

    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });
}


/* ============================================================
   GLOBAL UI API
   ============================================================ */

window.navigateTo = navigateTo;


/* ============================================================
   MOBILE NAVIGATION
   ============================================================ */

function initializeGlobalControls() {

    const mobileMenu =
        $("#mobileMenu");

    if (mobileMenu) {

        mobileMenu.addEventListener(
            "click",
            () => {

                const sidebar =
                    $("#sidebar");

                sidebar.classList.toggle(
                    "mobile-open"
                );
            }
        );
    }
}


function closeMobileSidebar() {

    const sidebar =
        $("#sidebar");

    if (sidebar) {

        sidebar.classList.remove(
            "mobile-open"
        );
    }
}


/* ============================================================
   ANALYSIS TABS
   ============================================================ */

function initializeAnalysisTabs() {

    $$(".analysis-tab").forEach(
        tab => {

            tab.addEventListener(
                "click",
                () => {

                    activateAnalysis(
                        tab.dataset.analysis
                    );
                }
            );
        }
    );
}


function activateAnalysis(
    analysisType
) {

    const panel =
        $(`#analysis-${analysisType}`);

    if (!panel) {
        return;
    }

    state.currentAnalysis =
        analysisType;


    $$(".analysis-tab").forEach(
        tab => {

            tab.classList.toggle(
                "active",
                tab.dataset.analysis ===
                analysisType
            );
        }
    );


    $$(".analysis-panel").forEach(
        analysisPanel => {

            analysisPanel.classList.remove(
                "active"
            );
        }
    );


    panel.classList.add("active");
}


window.activateAnalysis = activateAnalysis;


/* ============================================================
   QUICK ACTIONS
   ============================================================ */

function initializeQuickActions() {

    $$(".quick-action").forEach(
        button => {

            button.addEventListener(
                "click",
                () => {

                    navigateTo("phishing");

                    activateAnalysis(
                        button.dataset.analysis
                    );
                }
            );
        }
    );


    const openPhishingButton =
        $("#openPhishingButton");

    const newAnalysisModal =
        $("#newAnalysisModal");

    const closeNewAnalysisButton =
        $("#closeNewAnalysisButton");

    const openNewAnalysisModal = () => {

        if (!newAnalysisModal) {
            return;
        }

        newAnalysisModal.classList.remove("hidden");
        newAnalysisModal.setAttribute(
            "aria-hidden",
            "false"
        );

        document.body.style.overflow = "hidden";

        closeNewAnalysisButton?.focus();
    };

    const closeNewAnalysisModal = () => {

        if (!newAnalysisModal) {
            return;
        }

        newAnalysisModal.classList.add("hidden");
        newAnalysisModal.setAttribute(
            "aria-hidden",
            "true"
        );

        document.body.style.overflow = "";
    };

    if (openPhishingButton) {

        openPhishingButton.addEventListener(
            "click",
            openNewAnalysisModal
        );
    }

    closeNewAnalysisButton?.addEventListener(
        "click",
        closeNewAnalysisModal
    );

    $$('[data-new-analysis-close]').forEach(
        element => {

            element.addEventListener(
                "click",
                closeNewAnalysisModal
            );
        }
    );

    $$("[data-new-analysis]").forEach(
        option => {

            option.addEventListener(
                "click",
                () => {

                    const target =
                        option.dataset.newAnalysis;

                    if (!target) {
                        return;
                    }

                    closeNewAnalysisModal();

                    navigateTo(target);

                    if (target === "phishing") {

                        activateAnalysis(
                            option.dataset.analysis ||
                            "message"
                        );
                    }
                }
            );
        }
    );

    document.addEventListener(
        "keydown",
        event => {

            if (
                event.key === "Escape" &&
                newAnalysisModal &&
                !newAnalysisModal.classList.contains("hidden")
            ) {
                closeNewAnalysisModal();
            }
        }
    );
}


/* ============================================================
   MESSAGE INPUT
   ============================================================ */

function initializeMessageInput() {

    const textarea =
        $("#messageInput");

    const counter =
        $("#messageCount");

    if (!textarea) {
        return;
    }

    textarea.addEventListener(
        "input",
        () => {

            const length =
                textarea.value.length;

            counter.textContent =
                length.toLocaleString();

            if (
                length >
                CONFIG.MAX_MESSAGE_LENGTH
            ) {

                textarea.value =
                    textarea.value.slice(
                        0,
                        CONFIG.MAX_MESSAGE_LENGTH
                    );

                counter.textContent =
                    CONFIG.MAX_MESSAGE_LENGTH
                        .toLocaleString();
            }
        }
    );


    const clearButton =
        $("#clearMessage");

    if (clearButton) {

        clearButton.addEventListener(
            "click",
            () => {

                textarea.value = "";

                counter.textContent =
                    "0";

                resetResult("message");
            }
        );
    }


    const scanButton =
        $("#scanMessageButton");

    if (scanButton) {

        scanButton.addEventListener(
            "click",
            analyzeMessage
        );
    }
}


/* ============================================================
   MESSAGE ANALYSIS
   ============================================================ */

async function analyzeMessage() {

    const messageInput =
        $("#messageInput");

    const messageType =
        $("#messageType");

    const message =
        messageInput.value.trim();

    if (!message) {

        showToast(
            "Message required",
            "Paste a message before starting the analysis.",
            "error"
        );

        messageInput.focus();

        return;
    }


    if (
        message.length >
        CONFIG.MAX_MESSAGE_LENGTH
    ) {

        showToast(
            "Message too long",
            "Please keep the message within the supported input limit.",
            "error"
        );

        return;
    }


    setResultState(
        "message",
        "PROCESSING"
    );

    showLoading(
        "Analysing message",
        "CyberGuard is checking the message for phishing indicators."
    );


    try {

        const client =
            await ensureGradioClient();

        if (!client) {

            throw new Error(
                "CyberGuard engine is unavailable."
            );
        }


        /*
         * The endpoint shown in the user's Hugging Face
         * API documentation accepts:
         *
         * message: string
         */

        const result =
            await client.predict(
                CONFIG.ENDPOINTS.MESSAGE,
                {
                    message: message
                }
            );


        console.log(
            "[CyberGuard] Message result:",
            result
        );


        renderAnalysisResult(
            "message",
            result.data,
            {
                inputType:
                    messageType.value,

                originalInput:
                    message
            }
        );


        const phishingIncident = buildClientIncident("phishing", messageNormalized, message);
        addHistoryEntry({
            type: "Message",
            input:
                `${messageType.value} analysis`,
            result:
                summarizeResult(result.data),
            severity: phishingIncident.severity,
            riskScore: phishingIncident.risk_score,
            incidentId: phishingIncident.incident_id
        });


        showToast(
            "Analysis complete",
            "The message has been processed by the CyberGuard engine.",
            "success"
        );


    } catch (error) {

        console.error(
            "[CyberGuard] Message analysis failed:",
            error
        );

        renderAnalysisError(
            "message",
            error
        );

        showToast(
            "Analysis failed",
            getErrorMessage(error),
            "error"
        );

    } finally {

        hideLoading();
    }
}


window.analyzeMessage = analyzeMessage;



/* ============================================================
   ACCOUNT TAKEOVER DETECTION
   ============================================================ */

function initializeAccountTakeover() {
    const eventsInput = $("#takeoverEventsInput");
    const profilesInput = $("#takeoverProfilesInput");
    const analyzeButton = $("#analyzeTakeoverButton");
    const demoButton = $("#loadTakeoverDemo");
    const clearEventsButton = $("#clearTakeoverEvents");
    const clearProfilesButton = $("#clearTakeoverProfiles");

    if (!eventsInput || !analyzeButton) return;

    const setFileName = (id, name, loaded = false) => {
        const element = $(id);
        if (!element) return;
        element.textContent = name || "No file selected";
        element.classList.toggle("loaded", Boolean(loaded));
    };

    const updateEventCount = () => {
        const count = Array.isArray(state.takeoverEvents)
            ? state.takeoverEvents.length
            : 0;
        const counter = $("#takeoverEventCount");
        if (counter) counter.textContent = `${count} events`;
    };

    const parseCsv = (text) => {
        const rows = [];
        let row = [];
        let cell = "";
        let inQuotes = false;

        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            const next = text[i + 1];

            if (char === '"') {
                if (inQuotes && next === '"') {
                    cell += '"';
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (char === ',' && !inQuotes) {
                row.push(cell);
                cell = "";
            } else if ((char === '\n' || char === '\r') && !inQuotes) {
                if (char === '\r' && next === '\n') i++;
                row.push(cell);
                cell = "";
                if (row.some(value => String(value).trim() !== "")) rows.push(row);
                row = [];
            } else {
                cell += char;
            }
        }

        if (cell !== "" || row.length) {
            row.push(cell);
            if (row.some(value => String(value).trim() !== "")) rows.push(row);
        }

        if (!rows.length) {
            throw new Error("The CSV file is empty.");
        }

        const headers = rows[0].map((header, index) => {
            const value = String(header || "")
                .replace(/^\uFEFF/, "")
                .trim();
            return value || `column_${index + 1}`;
        });

        const duplicateHeaders = headers.filter((header, index) => headers.indexOf(header) !== index);
        if (duplicateHeaders.length) {
            throw new Error(`Duplicate CSV header: ${duplicateHeaders[0]}`);
        }

        return rows.slice(1).map(values => {
            const object = {};
            headers.forEach((header, index) => {
                object[header] = String(values[index] ?? "").trim();
            });
            return object;
        }).filter(object => Object.values(object).some(value => value !== ""));
    };

    const parseCsvFile = (file, kind) => {
        if (!file) return;

        const isCsv =
            file.name.toLowerCase().endsWith(".csv") ||
            file.type === "text/csv" ||
            file.type === "application/vnd.ms-excel";

        if (!isCsv) {
            showToast(
                "CSV file required",
                "Please choose a .csv file.",
                "error"
            );
            return;
        }

        const reader = new FileReader();

        reader.onload = () => {
            try {
                const parsed = parseCsv(String(reader.result || ""));

                if (!parsed.length && kind === "events") {
                    throw new Error("The event telemetry CSV contains no data rows.");
                }

                if (!parsed.length && kind === "profiles") {
                    throw new Error("The user profiles CSV contains no data rows.");
                }

                if (kind === "events") {
                    state.takeoverEvents = parsed;
                    setFileName(
                        "#takeoverEventsFileName",
                        `${file.name} • ${parsed.length} events`,
                        true
                    );
                    updateEventCount();
                    showToast(
                        "Telemetry uploaded",
                        `${parsed.length} event${parsed.length === 1 ? "" : "s"} loaded from ${file.name}.`,
                        "success"
                    );
                } else {
                    state.takeoverProfiles = parsed;
                    setFileName(
                        "#takeoverProfilesFileName",
                        `${file.name} • ${parsed.length} profiles`,
                        true
                    );
                    showToast(
                        "Profiles uploaded",
                        `${parsed.length} profile${parsed.length === 1 ? "" : "s"} loaded from ${file.name}.`,
                        "success"
                    );
                }

                resetAccountTakeoverResult();
            } catch (error) {
                showToast(
                    "Invalid CSV file",
                    error.message || "The uploaded file could not be read as CSV.",
                    "error"
                );
            } finally {
                if (kind === "events") eventsInput.value = "";
                else if (profilesInput) profilesInput.value = "";
            }
        };

        reader.onerror = () => {
            showToast(
                "File read failed",
                "CyberGuard could not read the selected CSV file.",
                "error"
            );
        };

        reader.readAsText(file);
    };

    eventsInput.addEventListener("change", () => {
        parseCsvFile(eventsInput.files?.[0], "events");
    });

    if (profilesInput) {
        profilesInput.addEventListener("change", () => {
            parseCsvFile(profilesInput.files?.[0], "profiles");
        });
    }

    const setupDropZone = (input, box, kind) => {
        if (!input || !box) return;

        ["dragenter", "dragover"].forEach(eventName => {
            box.addEventListener(eventName, event => {
                event.preventDefault();
                event.stopPropagation();
                box.classList.add("dragover");
            });
        });

        ["dragleave", "drop"].forEach(eventName => {
            box.addEventListener(eventName, event => {
                event.preventDefault();
                event.stopPropagation();
                box.classList.remove("dragover");
            });
        });

        box.addEventListener("drop", event => {
            const file = event.dataTransfer?.files?.[0];
            parseCsvFile(file, kind);
        });
    };

    setupDropZone(
        eventsInput,
        $("#takeoverEventsUploadBox"),
        "events"
    );

    setupDropZone(
        profilesInput,
        $("#takeoverProfilesUploadBox"),
        "profiles"
    );

    if (clearEventsButton) {
        clearEventsButton.addEventListener("click", () => {
            state.takeoverEvents = null;
            eventsInput.value = "";
            setFileName("#takeoverEventsFileName", "No file selected");
            updateEventCount();
            resetAccountTakeoverResult();
        });
    }

    if (clearProfilesButton) {
        clearProfilesButton.addEventListener("click", () => {
            state.takeoverProfiles = null;
            if (profilesInput) profilesInput.value = "";
            setFileName("#takeoverProfilesFileName", "No file selected");
            resetAccountTakeoverResult();
        });
    }

    if (demoButton) demoButton.addEventListener("click", loadAccountTakeoverDemo);
    analyzeButton.addEventListener("click", analyzeAccountTakeover);
}


function loadAccountTakeoverDemo() {
    const demoEvents = [
        {timestamp:"2026-10-03T10:00:00",user_id:"user001",login_status:"failed",ip_address:"203.0.113.10",location:"Unknown City",device:"Chrome-Windows",session_action:"login_failed"},
        {timestamp:"2026-10-03T10:01:00",user_id:"user001",login_status:"failed",ip_address:"203.0.113.10",location:"Unknown City",device:"Chrome-Windows",session_action:"login_failed"},
        {timestamp:"2026-10-03T10:02:00",user_id:"user001",login_status:"failed",ip_address:"203.0.113.10",location:"Unknown City",device:"Chrome-Windows",session_action:"login_failed"},
        {timestamp:"2026-10-03T10:03:00",user_id:"user001",login_status:"failed",ip_address:"203.0.113.10",location:"Unknown City",device:"Chrome-Windows",session_action:"login_failed"},
        {timestamp:"2026-10-03T10:04:00",user_id:"user001",login_status:"failed",ip_address:"203.0.113.10",location:"Unknown City",device:"Chrome-Windows",session_action:"login_failed"},
        {timestamp:"2026-10-03T10:05:00",user_id:"user002",login_status:"failed",ip_address:"203.0.113.10",location:"Unknown City",device:"Firefox-Linux",session_action:"login_failed"},
        {timestamp:"2026-10-03T10:06:00",user_id:"user003",login_status:"failed",ip_address:"203.0.113.10",location:"Unknown City",device:"Firefox-Linux",session_action:"login_failed"},
        {timestamp:"2026-10-03T10:07:00",user_id:"user004",login_status:"failed",ip_address:"203.0.113.10",location:"Unknown City",device:"Firefox-Linux",session_action:"login_failed"},
        {timestamp:"2026-10-03T10:08:00",user_id:"user005",login_status:"failed",ip_address:"203.0.113.10",location:"Unknown City",device:"Firefox-Linux",session_action:"login_failed"},
        {timestamp:"2026-10-03T10:09:00",user_id:"user006",login_status:"success",ip_address:"203.0.113.10",location:"Unknown City",device:"Unknown-Mobile",session_action:"privileged_action"}
    ];

    const demoProfiles = [
        {user_id:"user001",normal_locations:"Bhubaneswar",known_devices:"Edge-Windows"},
        {user_id:"user002",normal_locations:"Bhubaneswar",known_devices:"Chrome-Windows"},
        {user_id:"user003",normal_locations:"Cuttack",known_devices:"Chrome-Windows"},
        {user_id:"user004",normal_locations:"Bhubaneswar",known_devices:"Safari-Mac"},
        {user_id:"user005",normal_locations:"Puri",known_devices:"Chrome-Windows"},
        {user_id:"user006",normal_locations:"Bhubaneswar",known_devices:"Chrome-Windows"}
    ];

    state.takeoverEvents = demoEvents;
    state.takeoverProfiles = demoProfiles;

    const eventFileName = $("#takeoverEventsFileName");
    const profileFileName = $("#takeoverProfilesFileName");
    if (eventFileName) {
        eventFileName.textContent = `Demo scenario • ${demoEvents.length} events`;
        eventFileName.classList.add("loaded");
    }
    if (profileFileName) {
        profileFileName.textContent = `Demo scenario • ${demoProfiles.length} profiles`;
        profileFileName.classList.add("loaded");
    }

    const counter = $("#takeoverEventCount");
    if (counter) counter.textContent = `${demoEvents.length} events`;

    resetAccountTakeoverResult();
    showToast(
        "Demo scenario loaded",
        "A sample multi-signal account takeover scenario is ready to analyse.",
        "success"
    );
}


async function analyzeAccountTakeover() {
    const events = state.takeoverEvents;
    const profiles = state.takeoverProfiles;

    if (!Array.isArray(events) || events.length === 0) {
        showToast(
            "Telemetry required",
            "Upload an event telemetry CSV file before starting the analysis.",
            "error"
        );
        return;
    }

    if (events.length > 5000) {
        showToast("Too much telemetry", "Maximum 5000 telemetry events are supported per analysis.", "error");
        return;
    }

    if (profiles !== null && !Array.isArray(profiles)) {
        showToast(
            "Invalid profiles",
            "The uploaded user profiles must be a CSV file.",
            "error"
        );
        return;
    }

    setResultState("takeover","PROCESSING");
    showLoading(
        "Analysing account activity",
        "CyberGuard is checking authentication, device, location and session behaviour."
    );

    try {
        const response = await fetch("/api/account_takeover", {
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body:JSON.stringify({
                events,
                profiles,
                organisation: getOrganisationProfile().name,
                organisation_domain: getOrganisationProfile().domain
            })
        });

        /*
         * Read the body as text first: error responses from
         * proxies or static hosts are frequently HTML, and a
         * direct response.json() would surface a raw
         * SyntaxError instead of a readable message.
         */

        const responseText = await response.text();

        let data = null;

        try {
            data = responseText ? JSON.parse(responseText) : null;
        } catch {
            data = null;
        }

        if (!response.ok) {
            throw new Error(
                data?.detail ||
                data?.error ||
                `Account takeover analysis failed (HTTP ${response.status}).`
            );
        }

        renderAccountTakeoverResult(data);
        addUnifiedIncidents(data?.result?.incidents || []);
        const atoIncidents = data?.result?.incidents || [];
        const atoTop = atoIncidents[0] || {};
        addHistoryEntry({
            type:"Account Takeover",
            input:`${events.length} telemetry events`,
            result:summarizeAccountTakeover(data),
            severity: atoTop.severity,
            riskScore: atoTop.risk_score,
            incidentId: atoTop.incident_id
        });

        showToast(
            "Analysis complete",
            "Account activity has been processed by the CyberGuard takeover engine.",
            "success"
        );
    } catch (error) {
        console.error(
            "[CyberGuard] Account takeover analysis failed:",
            error
        );

        renderAccountTakeoverError(error);

        showToast(
            "Analysis failed",
            getErrorMessage(error),
            "error"
        );
    } finally {
        hideLoading();
    }
}

function storeResultForExport(type, response, meaning, recommendation) {

    window.lastCyberGuardResult = {
        type,
        result: response?.result || response,
        meaning,
        recommendation
    };

    setPdfExportReady(type, true);
}

function renderAccountTakeoverResult(response) {
    const result = response?.result || response;
    const summary = result?.summary || {};
    const accounts = Array.isArray(result?.accounts) ? result.accounts : [];
    const detections = Array.isArray(result?.detections) ? result.detections : [];

    $("#takeoverResultEmpty")?.classList.add("hidden");
    $("#takeoverResultContent")?.classList.remove("hidden");
    setResultState("takeover","COMPLETE");

    $("#takeoverUsersAnalyzed").textContent = String(summary.users_analyzed ?? 0);
    $("#takeoverAccountsFlagged").textContent = String(summary.accounts_flagged ?? 0);
    $("#takeoverDetectionEvents").textContent = String(summary.detection_events ?? detections.length ?? 0);
    $("#takeoverHighRisk").textContent = String(summary.high_risk ?? 0);
    $("#takeoverMediumRisk").textContent = String(summary.medium_risk ?? 0);
    $("#takeoverLowRisk").textContent = String(summary.low_risk ?? 0);

    const accountList = $("#takeoverAccountList");
    if (accountList) {
        accountList.innerHTML = accounts.length ? "" : `<div class="takeover-no-threat"><span>✓</span><div><strong>No accounts were flagged</strong><p>The supplied telemetry did not produce a risk report.</p></div></div>`;
        accounts.forEach(account => accountList.insertAdjacentHTML("beforeend",buildTakeoverAccountCard(account)));
    }

    const detectionList = $("#takeoverDetectionList");
    if (detectionList) {
        detectionList.innerHTML = detections.length ? "" : `<div class="takeover-no-threat compact"><span>✓</span><div><strong>No detector events returned</strong><p>No individual takeover indicators were triggered.</p></div></div>`;
        detections.slice(0,20).forEach(detection => detectionList.insertAdjacentHTML("beforeend",buildTakeoverDetectionCard(detection)));
    }

    const high = Number(summary.high_risk || 0);
    const medium = Number(summary.medium_risk || 0);
    const flagged = Number(summary.accounts_flagged || 0);
    const meaning = $("#takeoverMeaning");
    if (meaning) {
        if (high > 0) meaning.textContent = `${high} account${high === 1 ? "" : "s"} received a high-risk assessment. The engine found multiple or strong behavioural signals that warrant investigation.`;
        else if (medium > 0) meaning.textContent = `${medium} account${medium === 1 ? "" : "s"} received a medium-risk assessment. Suspicious behaviour was detected, but the evidence is not classified as high risk.`;
        else if (flagged > 0) meaning.textContent = `${flagged} account${flagged === 1 ? "" : "s"} appeared in the risk report, but none were classified as high or medium risk.`;
        else meaning.textContent = "No account takeover risk was identified from the supplied telemetry.";
    }
    const recommendation = $("#takeoverRecommendation");
    if (recommendation) {
        if (high > 0) recommendation.textContent = "Investigate high-risk accounts first, review recent authentication and session activity, and follow your organisation's incident-response procedure.";
        else if (medium > 0) recommendation.textContent = "Review the flagged accounts and their detector evidence before deciding whether additional verification or access controls are required.";
        else recommendation.textContent = "No immediate takeover response was indicated by the supplied telemetry. Continue monitoring account activity.";
    }
    const raw = $("#takeoverRaw");
    if (raw) raw.textContent = safePrettyPrint(response);

    storeResultForExport(
        "account_takeover",
        response,
        meaning?.textContent,
        recommendation?.textContent
    );
}

function buildTakeoverAccountCard(account) {
    const risk = String(account.risk_level || "UNKNOWN").toUpperCase();
    const riskClass = risk === "HIGH" ? "high" : risk === "MEDIUM" ? "medium" : "low";
    const detectors = Array.isArray(account.detectors_triggered) ? account.detectors_triggered : [];
    const reasons = Array.isArray(account.reasons) ? account.reasons : [];
    const classification = account.attack_type
        ? `<p class="unified-card-meta"><strong>ATTACK TYPE</strong> ${escapeHtml(account.attack_type)}</p>`
        : "";
    const confidence = account.confidence
        ? `<p class="unified-card-meta"><strong>CONFIDENCE</strong> ${escapeHtml(account.confidence)}${account.confidence_score != null ? ` (${escapeHtml(account.confidence_score)}/100)` : ""}</p>`
        : "";
    const actions = typeof account.recommended_actions === "string"
        ? account.recommended_actions.split("|").filter(Boolean).slice(0, 3)
        : Array.isArray(account.recommended_actions) ? account.recommended_actions.slice(0, 3) : [];
    const detectorHtml = detectors.length ? detectors.map(item => `<span>${escapeHtml(item)}</span>`).join("") : `<span>No detector names returned</span>`;
    const reasonHtml = reasons.length ? reasons.map(item => `<li>${escapeHtml(item)}</li>`).join("") : `<li>No additional evidence returned.</li>`;
    return `
        <article class="takeover-account-card ${riskClass}">
            <div class="takeover-account-top"><div><span class="takeover-account-label">ACCOUNT</span><strong>${escapeHtml(account.user_id ?? "Unknown user")}</strong></div><div class="takeover-risk-badge ${riskClass}">${escapeHtml(risk)} RISK</div></div>
            ${classification}
            ${confidence}
            <div class="takeover-account-score"><span>RISK SCORE</span><strong>${escapeHtml(account.risk_score ?? 0)}</strong></div>
            <div class="takeover-detector-tags">${detectorHtml}</div>
            <div class="takeover-reasons"><span>WHY IT WAS FLAGGED</span><ul>${reasonHtml}</ul></div>
            ${actions.length ? `<div class="unified-card-actions"><strong>RECOMMENDED RESPONSE</strong><ul>${actions.map(item => `<li>${escapeHtml(item.trim())}</li>`).join("")}</ul></div>` : ""}
        </article>`;
}

function buildTakeoverDetectionCard(detection) {
    const threat = detection.threat || "Detection event";
    const user = detection.user_id || "Multiple / source-level";
    const evidence = [];
    Object.entries(detection).forEach(([key,value]) => {
        if (["threat","user_id","risk"].includes(key)) return;
        if (value === null || value === undefined || value === "" || typeof value === "object") return;
        evidence.push(`${formatKey(key)}: ${value}`);
    });
    return `
        <div class="takeover-detection-card"><div class="takeover-detection-icon">!</div><div class="takeover-detection-main"><strong>${escapeHtml(threat)}</strong><span>${escapeHtml(String(user))}</span><p>${escapeHtml(evidence.slice(0,3).join(" · ") || "Detector triggered without additional display fields.")}</p></div><span class="takeover-detection-risk">${escapeHtml(String(detection.risk || "FLAGGED").toUpperCase())}</span></div>`;
}

function summarizeAccountTakeover(response) {
    const summary = response?.result?.summary || response?.summary || {};
    return `${summary.accounts_flagged ?? 0} flagged accounts / ${summary.detection_events ?? 0} detection events`;
}

function resetAccountTakeoverResult() {
    $("#takeoverResultEmpty")?.classList.remove("hidden");
    $("#takeoverResultContent")?.classList.add("hidden");
    setResultState("takeover","WAITING");
}

function renderAccountTakeoverError(error) {
    $("#takeoverResultEmpty")?.classList.add("hidden");
    $("#takeoverResultContent")?.classList.remove("hidden");
    setResultState("takeover","ERROR");
    ["takeoverUsersAnalyzed","takeoverAccountsFlagged","takeoverDetectionEvents","takeoverHighRisk","takeoverMediumRisk","takeoverLowRisk"].forEach(id => { const el=$("#"+id); if(el) el.textContent="—"; });
    $("#takeoverAccountList").innerHTML = `<div class="takeover-error-card"><div><strong>Analysis could not be completed</strong><p>${escapeHtml(getErrorMessage(error))}</p></div></div>`;
    $("#takeoverDetectionList").innerHTML = "";
    $("#takeoverMeaning").textContent = "The Account Takeover engine could not complete this analysis.";
    $("#takeoverRecommendation").textContent = "Check the API deployment and input format, then retry the analysis.";
    $("#takeoverRaw").textContent = error?.stack || String(error);
}

window.analyzeAccountTakeover = analyzeAccountTakeover;


/* ============================================================
   DIGITAL IMPERSONATION DETECTION
   ============================================================ */

/* The sender field accepts an email address or a phone number only:
   display names such as "IT Service Desk" are rejected so every
   detection is tied to real sending infrastructure. */

const IMPERSONATION_EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const IMPERSONATION_PHONE_PATTERN = /^\+?[\d\s().-]+$/;

function classifyImpersonationSender(value) {
    const sender = String(value || "").trim();

    if (!sender) return null;

    if (IMPERSONATION_EMAIL_PATTERN.test(sender)) return "email";

    if (!IMPERSONATION_PHONE_PATTERN.test(sender)) return null;

    const digits = sender.replace(/\D/g, "");

    if (digits.length < 7 || digits.length > 15) return null;

    return "phone";
}

function normaliseImpersonationPhone(value) {
    const sender = String(value || "").trim();
    const digits = sender.replace(/\D/g, "");

    return sender.startsWith("+") ? `+${digits}` : digits;
}

function updateImpersonationSenderState(value) {
    const sender = String(value || "").trim();
    const kind = classifyImpersonationSender(sender);
    const invalid = Boolean(sender) && !kind;

    $("#impersonationSenderInput")?.classList.toggle("invalid", invalid);

    const hint = $("#impersonationSenderHint");

    if (hint) {
        hint.classList.toggle("error", invalid);
        hint.textContent = invalid
            ? "Enter a valid email address (name@company.com) or phone number (+91 98765 43210)."
            : "Email address or phone number only — sender display names are not accepted.";
    }

    return kind;
}

function buildImpersonationMessage(sender, messageText) {
    const kind = classifyImpersonationSender(sender);

    if (!kind) return null;

    const address = String(sender).trim();
    const isEmail = kind === "email";

    /* Emails carry their sending domain; phone numbers are stored as
       the sending number itself so repeated numbers cluster into one
       campaign, matching the sample CSV convention. */
    const senderDomain = isEmail
        ? address.split("@")[1].toLowerCase()
        : normaliseImpersonationPhone(address);

    const profile = typeof getOrganisationProfile === "function"
        ? getOrganisationProfile()
        : { name: "", domain: "" };

    return {
        timestamp: new Date().toISOString(),
        message_id: `msg-${Date.now().toString(36)}`,
        channel: isEmail ? "email" : "sms",
        sender_name: isEmail ? address : senderDomain,
        sender_domain: senderDomain,
        message_text: messageText,
        organisation_context: profile.name,
        organisation_domain: profile.domain,
        context: "reported by the organisation"
    };
}

/* Demo dataset for this section.
   Every row describes an incident reported by the configured
   organisation: claimed entities, sender addresses, message text and
   reporting context all come from the organisation profile in
   Organisation Settings instead of unrelated third-party brands. */

function buildImpersonationDemoMessages(profile) {
    const org = profile?.name || "Acme Corporation";
    const domain = profile?.domain || "acme-corp.com";

    return [
        {
            timestamp: "2026-10-03T09:00:00",
            message_id: "msg001",
            channel: "sms",
            sender_name: "+911234567890",
            sender_domain: "+911234567890",
            claimed_identity: `${org} IT Helpdesk`,
            claimed_role: "IT administrator",
            claimed_organisation: org,
            message_text: `URGENT notice from ${org} IT: your network password will expire today. Confirm your OTP and current password on the verification form immediately or your account will be blocked. Do not share this with anyone.`,
            context: `reported by the ${org} service desk`
        },
        {
            timestamp: "2026-10-03T09:30:00",
            message_id: "msg002",
            channel: "email",
            sender_name: "hr@hr-update-portal.top",
            sender_domain: "hr-update-portal.top",
            claimed_identity: `${org} Payroll`,
            claimed_role: "hr manager",
            claimed_organisation: org,
            message_text: `Attention ${org} employees. Your salary revision is approved. Share your bank account number and OTP on this secure payroll form to update your records. Click the link below to submit details.`,
            context: `forwarded to the ${org} IT inbox by staff`
        },
        {
            timestamp: "2026-10-03T10:00:00",
            message_id: "msg003",
            channel: "email",
            sender_name: `ceo@${domain}`,
            sender_domain: domain,
            claimed_identity: `${org} CEO Office`,
            claimed_role: "CEO",
            claimed_organisation: org,
            message_text: `This is the ${org} CEO. We have a confidential board meeting today. I need you to change the vendor bank details immediately and transfer the advance payment before midnight. Do not discuss this with the finance department.`,
            context: `reported by the ${org} finance team`
        },
        {
            timestamp: "2026-10-03T10:30:00",
            message_id: "msg004",
            channel: "sms",
            sender_name: "+919876543210",
            sender_domain: "+919876543210",
            claimed_identity: `${org} Legal & Compliance`,
            claimed_role: "legal officer",
            claimed_organisation: org,
            message_text: `URGENT notice from ${org} Legal & Compliance: a case has been registered against you for money laundering. Your ${org} bank account will be frozen within 24 hours and a penalty of 50000 rupees has been imposed. Do not call anyone to verify.`,
            context: `received by ${org} staff on a company-issued mobile`
        },
        {
            timestamp: "2026-10-03T11:00:00",
            message_id: "msg005",
            channel: "email",
            sender_name: "accounts@invoice-approval.top",
            sender_domain: "invoice-approval.top",
            claimed_identity: `${org} Accounts`,
            claimed_role: "finance officer",
            claimed_organisation: org,
            message_text: `URGENT: the ${org} accounts department requires the vendor bank details changed today. Transfer the advance payment to the new beneficiary before midnight and confirm your OTP to authorise. Do not discuss this with anyone.`,
            context: `reported by the ${org} accounts team`
        },
        {
            timestamp: "2026-10-03T11:30:00",
            message_id: "msg006",
            channel: "sms",
            sender_name: "+919812345678",
            sender_domain: "+919812345678",
            claimed_identity: `${org} Security Team`,
            claimed_role: "security officer",
            claimed_organisation: org,
            message_text: `Your ${org} account is suspended. Confirm your OTP immediately on the verification link or your access will be blocked. Click here to verify now. Do not share this code with anyone.`,
            context: `flagged by ${org} IT security`
        }
    ];
}

function initializeDigitalImpersonation() {
    const senderInput = $("#impersonationSenderInput");
    const messageInput = $("#impersonationMessageInput");
    const analyzeButton = $("#analyzeImpersonationButton");
    const demoButton = $("#loadImpersonationDemo");

    if (!senderInput || !messageInput || !analyzeButton) return;

    const updateMessageCount = () => {
        const count = Array.isArray(state.impersonationMessages)
            ? state.impersonationMessages.length
            : 0;
        const counter = $("#impersonationMessageCount");
        if (counter) counter.textContent = `${count} message${count === 1 ? "" : "s"}`;
    };

    const syncFromFields = () => {
        const sender = senderInput.value.trim();
        const messageText = messageInput.value.trim();

        const senderKind = updateImpersonationSenderState(sender);

        state.impersonationMessages =
            senderKind && messageText
                ? [buildImpersonationMessage(sender, messageText)]
                : null;

        updateMessageCount();
        resetImpersonationResult();
    };

    [senderInput, messageInput].forEach(input => {
        input.addEventListener("input", syncFromFields);
    });

    if (demoButton) demoButton.addEventListener("click", loadImpersonationDemo);
    analyzeButton.addEventListener("click", analyzeDigitalImpersonation);
}

function loadImpersonationDemo() {
    const profile = getOrganisationProfile();

    const demoMessages = buildImpersonationDemoMessages(profile);

    demoMessages.forEach(message => {
        message.organisation_context = profile.name;
        message.organisation_domain = profile.domain;
    });

    state.impersonationMessages = demoMessages;

    const senderInput = $("#impersonationSenderInput");
    const messageInput = $("#impersonationMessageInput");
    const sample = demoMessages[1] || demoMessages[0] || {};

    if (senderInput) senderInput.value = sample.sender_name || "";
    if (messageInput) messageInput.value = sample.message_text || "";

    updateImpersonationSenderState(sample.sender_name);

    const counter = $("#impersonationMessageCount");
    if (counter) counter.textContent = `${demoMessages.length} messages (demo)`;

    resetImpersonationResult();
    showToast(
        "Demo scenario loaded",
        `${demoMessages.length} reported messages for ${profile.name} are ready to analyse. Senders are email addresses or phone numbers; editing either field analyses only that message.`,
        "success"
    );
}

async function analyzeDigitalImpersonation() {
    const messages = state.impersonationMessages;

    if (!Array.isArray(messages) || messages.length === 0) {
        const senderElement = $("#impersonationSenderInput");
        const messageElement = $("#impersonationMessageInput");
        const sender = (senderElement?.value || "").trim();
        const messageText = (messageElement?.value || "").trim();

        const senderKind = updateImpersonationSenderState(sender);

        if (!sender && !messageText) {
            showToast(
                "Sender and message required",
                "Enter the sender's email address or phone number, then paste the reported message.",
                "error"
            );
            senderElement?.focus();
        } else if (!sender) {
            showToast(
                "Sender required",
                "Enter the sender's email address or phone number before starting the analysis.",
                "error"
            );
            senderElement?.focus();
        } else if (!senderKind) {
            showToast(
                "Email or phone number required",
                "The sender field accepts only an email address or a phone number — no display names.",
                "error"
            );
            senderElement?.focus();
        } else {
            showToast(
                "Message required",
                "Paste the reported message before starting the analysis.",
                "error"
            );
            messageElement?.focus();
        }
        return;
    }

    if (messages.length > 5000) {
        showToast("Too many messages", "Maximum 5000 messages are supported per analysis.", "error");
        return;
    }

    if (messages.some(item => String(item?.message_text || "").length > CONFIG.MAX_MESSAGE_LENGTH)) {
        showToast("Message too long", "Keep each reported message within the supported input limit.", "error");
        return;
    }

    setResultState("impersonation", "PROCESSING");
    showLoading(
        "Analysing impersonation risk",
        "CyberGuard is checking identity claims, pressure tactics, threats and credential requests."
    );

    try {
        const response = await fetch("/api/digital_impersonation", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                messages,
                organisation: getOrganisationProfile().name,
                organisation_domain: getOrganisationProfile().domain
            })
        });

        const responseText = await response.text();

        let data = null;

        try {
            data = responseText ? JSON.parse(responseText) : null;
        } catch {
            data = null;
        }

        if (!response.ok) {
            throw new Error(
                data?.detail ||
                data?.error ||
                `Digital impersonation analysis failed (HTTP ${response.status}).`
            );
        }

        renderImpersonationResult(data);
        addUnifiedIncidents(data?.result?.incidents || []);
        const impersonationIncidents = data?.result?.incidents || [];
        const impersonationTop = impersonationIncidents[0] || {};
        addHistoryEntry({
            type: "Digital Impersonation",
            input: `${messages.length} reported messages`,
            result: summarizeImpersonation(data),
            severity: impersonationTop.severity,
            riskScore: impersonationTop.risk_score,
            incidentId: impersonationTop.incident_id
        });

        showToast(
            "Analysis complete",
            "Reported messages have been processed by the CyberGuard impersonation engine.",
            "success"
        );
    } catch (error) {
        console.error(
            "[CyberGuard] Digital impersonation analysis failed:",
            error
        );

        renderImpersonationError(error);

        showToast(
            "Analysis failed",
            getErrorMessage(error),
            "error"
        );
    } finally {
        hideLoading();
    }
}

function renderImpersonationResult(response) {
    const result = response?.result || response;
    const summary = result?.summary || {};
    const messages = Array.isArray(result?.messages) ? result.messages : [];
    const detections = Array.isArray(result?.detections) ? result.detections : [];
    const campaigns = Array.isArray(result?.campaigns) ? result.campaigns : [];

    $("#impersonationResultEmpty")?.classList.add("hidden");
    $("#impersonationResultContent")?.classList.remove("hidden");
    setResultState("impersonation", "COMPLETE");

    const setText = (id, value) => {
        const element = $(id);
        if (element) element.textContent = String(value);
    };

    setText("#impersonationMessagesAnalyzed", summary.messages_analyzed ?? 0);
    setText("#impersonationMessagesFlagged", summary.messages_flagged ?? 0);
    setText("#impersonationDetectionEvents", summary.detection_events ?? detections.length ?? 0);
    setText("#impersonationHighRisk", summary.high_risk ?? 0);
    setText("#impersonationMediumRisk", summary.medium_risk ?? 0);
    setText("#impersonationLowRisk", summary.low_risk ?? 0);

    const submittedMessages = Array.isArray(state.impersonationMessages) ? state.impersonationMessages : [];
    const senderLookup = new Map(
        submittedMessages.map(message => [
            String(message.message_id ?? ""),
            message.sender_name || ""
        ])
    );

    const messageList = $("#impersonationMessageList");
    if (messageList) {
        messageList.innerHTML = messages.length ? "" : `<div class="takeover-no-threat"><span>✓</span><div><strong>No messages were flagged</strong><p>The supplied messages did not produce an impersonation report.</p></div></div>`;
        messages.forEach(message => messageList.insertAdjacentHTML("beforeend", buildImpersonationMessageCard(message, senderLookup)));
    }

    const detectionList = $("#impersonationDetectionList");
    if (detectionList) {
        detectionList.innerHTML = detections.length ? "" : `<div class="takeover-no-threat compact"><span>✓</span><div><strong>No detector events returned</strong><p>No individual impersonation indicators were triggered.</p></div></div>`;
        detections.slice(0, 20).forEach(detection => detectionList.insertAdjacentHTML("beforeend", buildTakeoverDetectionCard(detection)));
    }

    const campaignSection = $("#impersonationCampaignSection");
    const campaignList = $("#impersonationCampaignList");

    if (campaignSection) {
        campaignSection.classList.toggle("hidden", campaigns.length === 0);
    }

    if (campaignList) {
        campaignList.innerHTML = campaigns.length ? "" : `<div class="takeover-no-threat compact"><span>✓</span><div><strong>No campaign clusters</strong><p>No repeated sender infrastructure was detected.</p></div></div>`;
        campaigns.forEach(campaign => campaignList.insertAdjacentHTML("beforeend", buildImpersonationCampaignCard(campaign)));
    }

    const high = Number(summary.high_risk || 0);
    const medium = Number(summary.medium_risk || 0);
    const flagged = Number(summary.messages_flagged || 0);
    const meaning = $("#impersonationMeaning");
    if (meaning) {
        if (high > 0) meaning.textContent = `${high} message${high === 1 ? "" : "s"} received a high-risk assessment. The engine found identity, pressure and request signals that strongly indicate impersonation.`;
        else if (medium > 0) meaning.textContent = `${medium} message${medium === 1 ? "" : "s"} received a medium-risk assessment. The message claims a trusted identity, but the supporting evidence is limited.`;
        else if (flagged > 0) meaning.textContent = `${flagged} message${flagged === 1 ? "" : "s"} appeared in the report, but none were classified as high or medium risk.`;
        else meaning.textContent = "No impersonation risk was identified from the supplied messages.";
    }

    const recommendation = $("#impersonationRecommendation");
    if (recommendation) {
        if (high > 0) recommendation.textContent = "Verify high-risk senders through a known contact channel, warn affected staff never to share OTPs or passwords, and block the reported sender addresses.";
        else if (medium > 0) recommendation.textContent = "Confirm the sender through an official channel before acting, and review whether the message matches any recent internal communication.";
        else recommendation.textContent = "No immediate impersonation response was indicated. Continue monitoring reported messages and keep awareness training active.";
    }

    const raw = $("#impersonationRaw");
    if (raw) raw.textContent = safePrettyPrint(response);

    storeResultForExport(
        "digital_impersonation",
        response,
        meaning?.textContent,
        recommendation?.textContent
    );
}

function buildImpersonationMessageCard(message, senderLookup) {
    const risk = String(message.risk_level || "UNKNOWN").toUpperCase();
    const riskClass = risk === "HIGH" ? "high" : risk === "MEDIUM" ? "medium" : "low";
    const detectors = Array.isArray(message.detectors_triggered) ? message.detectors_triggered : [];
    const reasons = Array.isArray(message.reasons) ? message.reasons : [];

    const submittedSender = senderLookup?.get(String(message.message_id ?? "")) || "";
    const senderAddress = submittedSender || message.sender_name || message.sender_domain || "";
    const claimed = message.claimed_identity || message.claimed_organisation || senderAddress;
    const channel = message.channel ? String(message.channel).toUpperCase() : "MESSAGE";

    const detectorHtml = detectors.length
        ? detectors.map(item => `<span>${escapeHtml(item)}</span>`).join("")
        : `<span>No detector names returned</span>`;

    const reasonHtml = reasons.length
        ? reasons.map(item => `<li>${escapeHtml(item)}</li>`).join("")
        : `<li>No additional evidence returned.</li>`;

    const excerpt = message.message_text
        ? `<p class="takeover-excerpt">${escapeHtml(String(message.message_text).slice(0, 180))}${String(message.message_text).length > 180 ? "…" : ""}</p>`
        : "";

    const classification = message.attack_category
        ? `<p class="unified-card-meta"><strong>ATTACK TYPE</strong> ${escapeHtml(message.attack_category)}</p>`
        : "";
    const confidence = message.confidence
        ? `<p class="unified-card-meta"><strong>CONFIDENCE</strong> ${escapeHtml(message.confidence)}${message.confidence_score != null ? ` (${escapeHtml(message.confidence_score)}/100)` : ""}</p>`
        : "";
    const actions = Array.isArray(message.recommended_actions) && message.recommended_actions.length
        ? `<div class="unified-card-actions"><strong>RECOMMENDED RESPONSE</strong><ul>${message.recommended_actions.slice(0,3).map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul></div>`
        : "";

    const senderLine = senderAddress
        ? `<p class="takeover-sender">Sender: ${escapeHtml(senderAddress)}</p>`
        : "";

    return `
        <article class="takeover-account-card ${riskClass}">
            <div class="takeover-account-top"><div><span class="takeover-account-label">${escapeHtml(channel)} · ${escapeHtml(message.message_id ?? "Unknown message")}</span><strong>${escapeHtml(claimed || "Unattributed message")}</strong></div><div class="takeover-risk-badge ${riskClass}">${escapeHtml(risk)} RISK</div></div>
            ${senderLine}
            ${classification}
            ${confidence}
            <div class="takeover-account-score"><span>RISK SCORE</span><strong>${escapeHtml(message.risk_score ?? 0)}</strong></div>
            ${excerpt}
            <div class="takeover-detector-tags">${detectorHtml}</div>
            <div class="takeover-reasons"><span>WHY IT WAS FLAGGED</span><ul>${reasonHtml}</ul></div>
            ${actions}
        </article>`;
}

function buildImpersonationCampaignCard(campaign) {
    const count = campaign.message_count ?? 0;
    const threats = campaign.threats || "No detector names";
    const threatList = String(threats)
        .split(",")
        .map(item => item.trim())
        .filter(Boolean);

    const threatHtml = threatList.length
        ? threatList.map(item => `<span>${escapeHtml(item)}</span>`).join("")
        : `<span>No detector names</span>`;

    return `
        <div class="takeover-detection-card">
            <div class="takeover-detection-icon">⌁</div>
            <div class="takeover-detection-main">
                <strong>${escapeHtml(campaign.campaign_key ?? "Unknown sender")}</strong>
                <span>${escapeHtml(String(count))} message${Number(count) === 1 ? "" : "s"} from this sender</span>
                <div class="takeover-detector-tags">${threatHtml}</div>
            </div>
        </div>`;
}

function summarizeImpersonation(response) {
    const summary = response?.result?.summary || response?.summary || {};
    return `${summary.messages_flagged ?? 0} flagged messages / ${summary.detection_events ?? 0} detection events`;
}

function resetImpersonationResult() {
    $("#impersonationResultEmpty")?.classList.remove("hidden");
    $("#impersonationResultContent")?.classList.add("hidden");
    setResultState("impersonation", "WAITING");
}

function renderImpersonationError(error) {
    $("#impersonationResultEmpty")?.classList.add("hidden");
    $("#impersonationResultContent")?.classList.remove("hidden");
    setResultState("impersonation", "ERROR");

    [
        "impersonationMessagesAnalyzed",
        "impersonationMessagesFlagged",
        "impersonationDetectionEvents",
        "impersonationHighRisk",
        "impersonationMediumRisk",
        "impersonationLowRisk"
    ].forEach(id => {
        const element = $(`#${id}`);
        if (element) element.textContent = "—";
    });

    const messageList = $("#impersonationMessageList");
    if (messageList) {
        messageList.innerHTML = `<div class="takeover-error-card"><div><strong>Analysis could not be completed</strong><p>${escapeHtml(getErrorMessage(error))}</p></div></div>`;
    }

    const detectionList = $("#impersonationDetectionList");
    if (detectionList) detectionList.innerHTML = "";

    const campaignList = $("#impersonationCampaignList");
    if (campaignList) campaignList.innerHTML = "";

    const meaning = $("#impersonationMeaning");
    if (meaning) meaning.textContent = "The Digital Impersonation engine could not complete this analysis.";

    const recommendation = $("#impersonationRecommendation");
    if (recommendation) recommendation.textContent = "Check the API deployment and input format, then retry the analysis.";

    const raw = $("#impersonationRaw");
    if (raw) raw.textContent = error?.stack || String(error);
}

window.analyzeDigitalImpersonation = analyzeDigitalImpersonation;


/* ============================================================
   URL CONTROLS
   ============================================================ */

function initializeUrlControls() {

    $$("[data-url-mode]").forEach(
        button => {

            button.addEventListener(
                "click",
                () => {

                    state.currentUrlMode =
                        button.dataset.urlMode;

                    $$("[data-url-mode]").forEach(
                        modeButton => {

                            modeButton.classList.toggle(
                                "active",
                                modeButton.dataset.urlMode ===
                                state.currentUrlMode
                            );
                        }
                    );

                    updateUrlModeUI();
                }
            );
        }
    );


    const urlButton =
        $("#scanUrlButton");

    if (urlButton) {

        urlButton.addEventListener(
            "click",
            analyzeUrl
        );
    }


    const urlInput =
        $("#urlInput");

    if (urlInput) {

        urlInput.addEventListener(
            "keydown",
            event => {

                if (
                    event.key === "Enter"
                ) {

                    event.preventDefault();

                    analyzeUrl();
                }
            }
        );
    }
}


function updateUrlModeUI() {

    const urlInput =
        $("#urlInput");

    if (!urlInput) {
        return;
    }


    if (
        state.currentUrlMode ===
        "website"
    ) {

        urlInput.placeholder =
            "https://example.com/login";

    } else {

        urlInput.placeholder =
            "https://suspicious-domain.example/login";
    }
}


/* ============================================================
   URL ANALYSIS
   ============================================================ */

async function analyzeUrl() {

    const urlInput =
        $("#urlInput");

    const url =
        urlInput.value.trim();


    if (!url) {

        showToast(
            "URL required",
            "Enter a website or URL before starting the analysis.",
            "error"
        );

        urlInput.focus();

        return;
    }


    if (!isValidUrl(url)) {

        showToast(
            "Invalid URL",
            "Please enter a complete URL such as https://example.com.",
            "error"
        );

        return;
    }


    setResultState(
        "url",
        "PROCESSING"
    );

    showLoading(
        state.currentUrlMode === "website"
            ? "Analysing website"
            : "Analysing URL",
        "CyberGuard is checking the destination for suspicious indicators."
    );


    try {

        const client =
            await ensureGradioClient();

        if (!client) {

            throw new Error(
                "CyberGuard engine is unavailable."
            );
        }


        /*
         * The endpoint shown in the user's Hugging Face
         * API documentation accepts:
         *
         * url: string
         */

        const result =
            await client.predict(
                CONFIG.ENDPOINTS.WEBSITE,
                {
                    url: url
                }
            );


        console.log(
            "[CyberGuard] URL result:",
            result
        );


        renderAnalysisResult(
            "url",
            result.data,
            {
                originalInput:
                    url,

                inputType:
                    state.currentUrlMode === "website"
                        ? "Fraudulent Website"
                        : "Malicious / Deceptive URL"
            }
        );


        addHistoryEntry({
            type:
                state.currentUrlMode === "website"
                    ? "Website"
                    : "URL",

            input:
                url,

            result:
                summarizeResult(result.data)
        });


        showToast(
            "Analysis complete",
            "The destination has been processed by the CyberGuard engine.",
            "success"
        );


    } catch (error) {

        console.error(
            "[CyberGuard] URL analysis failed:",
            error
        );

        renderAnalysisError(
            "url",
            error
        );

        showToast(
            "Analysis failed",
            getErrorMessage(error),
            "error"
        );

    } finally {

        hideLoading();
    }
}


window.analyzeUrl = analyzeUrl;


/* ============================================================
   URL VALIDATION
   ============================================================ */

function isValidUrl(value) {

    try {

        const url =
            new URL(value);

        return (
            url.protocol === "http:" ||
            url.protocol === "https:"
        );

    } catch {

        return false;
    }
}


/* ============================================================
   QR CONTROLS
   ============================================================ */

function initializeQrControls() {

    const fileInput =
        $("#qrInput");

    const chooseButton =
        $("#chooseQrButton");

    const dropZone =
        $("#qrDropZone");

    const removeButton =
        $("#removeQrFile");

    const scanButton =
        $("#scanQrButton");


    if (
        !fileInput ||
        !dropZone
    ) {

        return;
    }


    chooseButton.addEventListener(
        "click",
        () => {

            fileInput.click();
        }
    );


    fileInput.addEventListener(
        "change",
        () => {

            if (
                fileInput.files &&
                fileInput.files[0]
            ) {

                setQrFile(
                    fileInput.files[0]
                );
            }
        }
    );


    [
        "dragenter",
        "dragover"
    ].forEach(
        eventName => {

            dropZone.addEventListener(
                eventName,
                event => {

                    event.preventDefault();

                    dropZone.classList.add(
                        "dragover"
                    );
                }
            );
        }
    );


    [
        "dragleave",
        "drop"
    ].forEach(
        eventName => {

            dropZone.addEventListener(
                eventName,
                event => {

                    event.preventDefault();

                    dropZone.classList.remove(
                        "dragover"
                    );
                }
            );
        }
    );


    dropZone.addEventListener(
        "drop",
        event => {

            const files =
                event.dataTransfer.files;

            if (
                files &&
                files[0]
            ) {

                setQrFile(
                    files[0]
                );
            }
        }
    );


    removeButton.addEventListener(
        "click",
        clearQrFile
    );


    scanButton.addEventListener(
        "click",
        analyzeQr
    );
}


/* ============================================================
   SET QR FILE
   ============================================================ */

function setQrFile(file) {

    if (!file) {
        return;
    }


    if (
        !file.type.startsWith("image/")
    ) {

        showToast(
            "Invalid file",
            "Please select a PNG, JPG or WEBP image.",
            "error"
        );

        return;
    }


    if (
        file.size >
        CONFIG.MAX_QR_SIZE
    ) {

        showToast(
            "File too large",
            "Please choose an image smaller than 10 MB.",
            "error"
        );

        return;
    }


    state.selectedQrFile =
        file;


    $("#qrFileName").textContent =
        file.name;

    $("#qrFileSize").textContent =
        formatFileSize(file.size);


    $("#selectedQrFile")
        .classList.remove(
            "hidden"
        );


    $("#scanQrButton")
        .disabled =
        false;
}


/* ============================================================
   CLEAR QR
   ============================================================ */

function clearQrFile() {

    state.selectedQrFile =
        null;

    const input =
        $("#qrInput");

    if (input) {
        input.value = "";
    }

    $("#selectedQrFile")
        .classList.add(
            "hidden"
        );

    $("#scanQrButton")
        .disabled =
        true;

    resetResult("qr");
}


/* ============================================================
   QR ANALYSIS
   ============================================================ */

async function analyzeQr() {

    const file =
        state.selectedQrFile;


    if (!file) {

        showToast(
            "QR image required",
            "Upload a QR code image before starting the analysis.",
            "error"
        );

        return;
    }


    setResultState(
        "qr",
        "PROCESSING"
    );

    showLoading(
        "Scanning QR code",
        "CyberGuard is processing the uploaded QR image."
    );


    try {

        const client =
            await ensureGradioClient();

        if (!client) {

            throw new Error(
                "CyberGuard engine is unavailable."
            );
        }


        if (
            typeof state.gradioHandleFile !==
            "function"
        ) {

            throw new Error(
                "The Gradio file handler could not be loaded."
            );
        }


        /*
         * The endpoint shown in the user's Hugging Face
         * API documentation accepts:
         *
         * image: File / Blob / Buffer
         *
         * handle_file() converts the browser File
         * into the appropriate Gradio file input.
         */

        const result =
            await client.predict(
                CONFIG.ENDPOINTS.QR,
                {
                    image:
                        state.gradioHandleFile(
                            file
                        )
                }
            );


        console.log(
            "[CyberGuard] QR result:",
            result
        );


        renderAnalysisResult(
            "qr",
            result.data,
            {
                inputType:
                    "QR Code",

                originalInput:
                    file.name
            }
        );
        addUnifiedIncidents([buildClientIncident("phishing", normalizeResult(result.data), file.name)]);


        addHistoryEntry({
            type:
                "QR Code",

            input:
                file.name,

            result:
                summarizeResult(result.data)
        });


        showToast(
            "QR analysis complete",
            "The QR image has been processed by the CyberGuard engine.",
            "success"
        );


    } catch (error) {

        console.error(
            "[CyberGuard] QR analysis failed:",
            error
        );

        renderAnalysisError(
            "qr",
            error
        );

        showToast(
            "QR analysis failed",
            getErrorMessage(error),
            "error"
        );

    } finally {

        hideLoading();
    }
}


window.analyzeQr = analyzeQr;


/* ============================================================
   ENSURE GRADIO CLIENT
   ============================================================ */

async function ensureGradioClient() {

    if (
        state.gradioClient
    ) {

        return state.gradioClient;
    }


    return await initializeGradioClient();
}


/* ============================================================
   RESULT STATE
   ============================================================ */

function setResultState(
    type,
    status
) {

    const stateElement =
        $(`#${type}ResultState`);

    if (!stateElement) {
        return;
    }


    stateElement.className =
        "result-state";


    if (
        status ===
        "PROCESSING"
    ) {

        stateElement.classList.add(
            "processing"
        );
    }


    if (
        status ===
        "COMPLETE"
    ) {

        stateElement.classList.add(
            "success"
        );
    }


    if (
        status ===
        "ERROR"
    ) {

        stateElement.classList.add(
            "danger"
        );
    }


    stateElement.textContent =
        status;
}


/* ============================================================
   PHISHING STRUCTURAL PREFLIGHT
   ============================================================ */

function applyPhishingPreflight(normalized, input, type) {
    if (!normalized || !input) return normalized;
    const value = String(input).trim();
    const findings = [];

    if (type === "url" || type === "website") {
        try {
            const url = new URL(value);
            const host = url.hostname.toLowerCase();
            if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) findings.push("Destination uses a raw IP address instead of a conventional domain");
            if (host.includes("xn--")) findings.push("Destination uses punycode, which can hide lookalike characters");
            if (host.split(".").length >= 5) findings.push("Destination contains an unusually deep subdomain chain");
            if (/@/.test(value)) findings.push("URL contains an @ character that can obscure the actual destination");
            if (["zip","top","xyz","click","work","support","live","buzz"].includes(host.split(".").pop())) findings.push("Destination uses a commonly abused or high-risk top-level domain");
            if (url.username || url.password) findings.push("URL contains embedded credentials/user information");
        } catch {}
    }

    if (type === "message") {
        const lower = value.toLowerCase();
        if (/(otp|password|pin|cvv|verification code|credentials)/i.test(lower) && /(send|share|provide|enter|submit|reply|give|confirm)/i.test(lower)) {
            findings.push("Message structurally contains a sensitive-information request");
        }
        if (/(urgent|immediately|final warning|account.*suspend|legal action)/i.test(lower)) {
            findings.push("Message contains social-engineering pressure language");
        }
    }

    if (findings.length) {
        normalized.indicators = [...new Set([...normalized.indicators, ...findings])];
        if (!normalized.recommendation) {
            normalized.recommendation = "Verify the sender or destination independently before opening links or sharing sensitive information.";
        }
    }
    return normalized;
}

/* ============================================================
   RENDER ANALYSIS RESULT
   ============================================================ */

function renderAnalysisResult(
    type,
    rawData,
    metadata = {}
) {

    const initialNormalized = normalizeResult(rawData);
    const normalized =
        applyPhishingPreflight(
            initialNormalized,
            metadata.originalInput || initialNormalized.payload,
            type
        );


    const empty =
        $(`#${type}ResultEmpty`);

    const content =
        $(`#${type}ResultContent`);


    if (empty) {
        empty.classList.add(
            "hidden"
        );
    }

    if (content) {
        content.classList.remove(
            "hidden"
        );
    }


    setResultState(
        type,
        "COMPLETE"
    );


    const risk =
        determineRisk(
            normalized
        );


    const indicator =
        $(`#${type}RiskIndicator`);

    const label =
        $(`#${type}RiskLabel`);


    if (indicator) {

        indicator.className =
            "risk-indicator";

        indicator.classList.add(
            risk.className
        );
    }


    if (label) {

        label.textContent =
            risk.label;
    }


    const title =
        $(`#${type}ThreatTitle`);

    if (title) {

        title.textContent =
            risk.title;
    }


    const description =
        $(`#${type}ThreatDescription`);

    if (description) {

        description.textContent =
            risk.description;
    }


    const confidence =
        $(`#${type}Confidence`);

    if (
        confidence &&
        normalized.confidence !== null
    ) {

        confidence.textContent =
            formatConfidence(
                normalized.confidence
            );
    }


    const inputType =
        $(`#${type}InputType`);

    if (
        inputType &&
        metadata.inputType
    ) {

        inputType.textContent =
            metadata.inputType;
    }


    const indicators =
        $(`#${type}Indicators`);

    if (indicators) {

        indicators.innerHTML = "";

        const items =
            buildIndicators(
                normalized
            );

        items.forEach(
            item => {

                const element =
                    document.createElement(
                        "div"
                    );

                element.className =
                    "indicator";

                element.textContent =
                    item;

                indicators.appendChild(
                    element
                );
            }
        );
    }


    const meaning =
        $(`#${type}Meaning`);

    if (meaning) {
        meaning.textContent =
            normalized.message ||
            risk.description;
    }

    const recommendation =
        $(`#${type}Recommendation`);

    if (recommendation) {
        recommendation.textContent =
            normalized.recommendation ||
            getDefaultRecommendation(risk.className, type);
    }

    const analysedUrl =
        $("#analysedUrl");

    if (
        type === "url" &&
        analysedUrl &&
        metadata.originalInput
    ) {

        analysedUrl.textContent =
            metadata.originalInput;
    }


    const raw =
        $(`#${type}Raw`);

    if (raw) {

        raw.textContent =
            safePrettyPrint(
                rawData
            );
    }


    /*
     * The engine may return a different structure depending
     * on how cyberphishing_engine.py formats its output.
     * We therefore preserve the complete raw response while
     * extracting common fields where possible.
     */

    console.log(
        `[CyberGuard] Normalized ${type} result:`,
        normalized
    );
}


/* ============================================================
   NORMALIZE RESULT
   ============================================================ */

function normalizeResult(data) {

    let value = unwrapGradioData(data);

    if (typeof value === "string") {
        const parsed = tryParseJson(value);
        if (parsed !== null) {
            value = parsed;
        }
    }

    const result = {
        raw: value,
        label: null,
        prediction: null,
        confidence: null,
        riskLevel: null,
        status: null,
        riskScore: null,
        indicatorScore: null,
        indicators: [],
        message: null,
        threat: null,
        recommendation: null,
        payload: null,
        detectedCategories: [],
        highRiskCombinations: []
    };

    if (value === null || value === undefined) {
        return result;
    }

    if (typeof value === "string") {
        result.message = value;
        result.label = value;
        return result;
    }

    if (Array.isArray(value)) {
        value.forEach(item => {
            if (item && typeof item === "object") {
                mergeObjectFields(result, item);
            } else if (typeof item === "string") {
                result.indicators.push(item.trim());
            }
        });
        return result;
    }

    if (typeof value === "object") {
        mergeObjectFields(result, value);
        return result;
    }

    result.message = String(value);
    return result;
}


/* ============================================================
   MERGE OBJECT FIELDS
   ============================================================ */

function mergeObjectFields(result, object) {

    if (!object || typeof object !== "object") {
        return;
    }

    /*
     * CyberGuard's engine commonly returns:
     *
     * [
     *   {
     *     payload: "...",
     *     payload_type: "TEXT",
     *     analysis: {
     *       message: "...",
     *       status: "...",
     *       risk_level: "...",
     *       risk_score: 0,
     *       model_prediction: "benign",
     *       model_confidence: 100,
     *       indicator_score: 0,
     *       high_risk_combinations: [],
     *       detected_categories: {},
     *       recommendation: "..."
     *     }
     *   }
     * ]
     *
     * The old renderer only inspected the outer object, which is why
     * the UI fell back to a generic result and exposed the raw JSON.
     * Always inspect the nested analysis object first.
     */
    if (object.analysis && typeof object.analysis === "object") {
        mergeObjectFields(result, object.analysis);
    }

    if (object.result && typeof object.result === "object") {
        mergeObjectFields(result, object.result);
    }

    const labelKeys = [
        "model_prediction",
        "prediction",
        "predicted_label",
        "label",
        "risk_level",
        "risk",
        "threat",
        "category",
        "class",
        "status",
        "result"
    ];

    if (!result.label) {
        for (const key of labelKeys) {
            if (object[key] !== undefined && object[key] !== null) {
                if (typeof object[key] !== "object") {
                    result.label = String(object[key]);
                    break;
                }
            }
        }
    }

    if (!result.prediction) {
        const prediction =
            object.model_prediction ??
            object.prediction ??
            object.predicted_label;

        if (prediction !== undefined && prediction !== null) {
            result.prediction = String(prediction);
        }
    }

    const confidenceKeys = [
        "model_confidence",
        "confidence",
        "score",
        "probability",
        "phishing_probability"
    ];

    if (result.confidence === null) {
        for (const key of confidenceKeys) {
            if (object[key] !== undefined && object[key] !== null) {
                const number = Number(object[key]);
                if (Number.isFinite(number)) {
                    result.confidence = number;
                    break;
                }
            }
        }
    }

    const riskLevel =
        object.risk_level ??
        object.riskLevel;

    if (riskLevel !== undefined && riskLevel !== null) {
        result.riskLevel = String(riskLevel);
    }

    const status = object.status;
    if (status !== undefined && status !== null) {
        result.status = String(status);
    }

    if (object.risk_score !== undefined && object.risk_score !== null) {
        const n = Number(object.risk_score);
        if (Number.isFinite(n)) result.riskScore = n;
    }

    if (object.indicator_score !== undefined && object.indicator_score !== null) {
        const n = Number(object.indicator_score);
        if (Number.isFinite(n)) result.indicatorScore = n;
    }

    const recommendation =
        object.recommendation ??
        object.recommended_action ??
        object.action;

    if (recommendation !== undefined && recommendation !== null) {
        if (typeof recommendation === "string") {
            result.recommendation = recommendation;
        } else {
            const values = flattenStrings(recommendation);
            result.recommendation = values.join(" ");
        }
    }

    const payload =
        object.payload ??
        object.decoded_payload ??
        object.decoded_content ??
        object.url;

    if (payload !== undefined && payload !== null && !result.payload) {
        if (typeof payload === "string") {
            result.payload = payload;
        }
    }

    const categoryValue =
        object.detected_categories ??
        object.categories;

    if (categoryValue !== undefined && categoryValue !== null) {
        result.detectedCategories.push(
            ...flattenStrings(categoryValue)
        );
    }

    if (object.high_risk_combinations !== undefined) {
        result.highRiskCombinations.push(
            ...flattenStrings(object.high_risk_combinations)
        );
    }

    const indicatorKeys = [
        "indicators",
        "features",
        "reasons",
        "signals",
        "findings",
        "detections"
    ];

    for (const key of indicatorKeys) {
        if (object[key] !== undefined && object[key] !== null) {
            result.indicators.push(
                ...flattenStrings(object[key])
            );
        }
    }

    const messageKeys = [
        "message",
        "explanation",
        "description",
        "details"
    ];

    if (!result.message) {
        for (const key of messageKeys) {
            if (typeof object[key] === "string") {
                result.message = object[key];
                break;
            }
        }
    }

    if (!result.message && result.status) {
        result.message = result.status;
    }

    if (!result.threat) {
        result.threat =
            result.prediction ||
            result.riskLevel ||
            result.label;
    }
}


/* ============================================================
   UNWRAP GRADIO DATA
   ============================================================ */

function unwrapGradioData(data) {

    let value =
        data;


    /*
     * Some Gradio functions return:
     *
     * [value]
     *
     * while others can return objects.
     */

    if (
        Array.isArray(value) &&
        value.length === 1
    ) {

        value =
            value[0];
    }


    return value;
}


/* ============================================================
   TRY JSON
   ============================================================ */

function tryParseJson(value) {

    if (
        typeof value !==
        "string"
    ) {

        return null;
    }


    try {

        return JSON.parse(
            value
        );

    } catch {

        return null;
    }
}


/* ============================================================
   FLATTEN STRINGS
   ============================================================ */

function flattenStrings(
    value
) {

    const output = [];


    function walk(item) {

        if (
            item === null ||
            item === undefined
        ) {

            return;
        }


        if (
            typeof item ===
            "string"
        ) {

            const cleaned =
                item.trim();

            if (cleaned) {

                output.push(
                    cleaned
                );
            }

            return;
        }


        if (
            typeof item ===
            "number" ||
            typeof item ===
            "boolean"
        ) {

            output.push(
                String(item)
            );

            return;
        }


        if (
            Array.isArray(item)
        ) {

            item.forEach(
                walk
            );

            return;
        }


        if (
            typeof item ===
            "object"
        ) {

            Object.entries(
                item
            ).forEach(
                ([key, val]) => {

                    if (
                        typeof val ===
                        "string" ||
                        typeof val ===
                        "number" ||
                        typeof val ===
                        "boolean"
                    ) {

                        output.push(
                            `${formatKey(key)}: ${val}`
                        );

                    } else {

                        walk(val);
                    }
                }
            );
        }
    }


    walk(value);


    return [
        ...new Set(output)
    ];
}


/* ============================================================
   FORMAT KEY
   ============================================================ */

function formatKey(key) {

    return String(key)
        .replace(
            /[_-]+/g,
            " "
        )
        .replace(
            /\b\w/g,
            char =>
                char.toUpperCase()
        );
}


/* ============================================================
   DETERMINE RISK
   ============================================================ */

function determineRisk(normalized) {

    const prediction = String(
        normalized.prediction || normalized.label || ""
    ).toLowerCase();

    const riskLevel = String(
        normalized.riskLevel || ""
    ).toLowerCase();

    const status = String(
        normalized.status || ""
    ).toLowerCase();

    const message = String(
        normalized.message || normalized.threat || ""
    ).toLowerCase();

    const combined = `${prediction} ${riskLevel} ${status} ${message}`;

    const danger = [
        "phishing",
        "malicious",
        "malware",
        "dangerous",
        "fraudulent",
        "suspicious",
        "scam",
        "unsafe",
        "high risk",
        "critical",
        "attack",
        "credential theft",
        "credential theft",
        "spam"
    ].some(word => combined.includes(word));

    const safe = [
        "benign",
        "safe",
        "legitimate",
        "ham",
        "clean",
        "low risk",
        "no immediate threat",
        "no threat",
        "not phishing"
    ].some(word => combined.includes(word));

    if (danger && !safe) {
        return {
            className: "danger",
            label: "HIGH RISK",
            title: "Potential threat detected",
            description:
                "CyberGuard found signals associated with a potentially unsafe or deceptive input. Treat it with caution."
        };
    }

    if (safe && !danger) {
        return {
            className: "safe",
            label: "LOW RISK",
            title: "No immediate threat detected",
            description:
                "The connected detection engine classified this input as low risk based on the signals it returned."
        };
    }

    const confidence = normalized.confidence;

    if (confidence !== null) {
        const normalizedConfidence = normalizeConfidence(confidence);

        if (normalizedConfidence >= 0.75) {
            return {
                className: "danger",
                label: "HIGH RISK",
                title: "High-confidence threat classification",
                description:
                    "The detection engine returned a high-confidence threat classification."
            };
        }

        if (normalizedConfidence >= 0.45) {
            return {
                className: "warning",
                label: "REVIEW",
                title: "Review recommended",
                description:
                    "The engine returned signals that deserve review before the input is treated as safe."
            };
        }
    }

    return {
        className: "warning",
        label: "REVIEW",
        title: "Analysis completed",
        description:
            "The engine returned a result, but it did not provide enough clear information for a stronger classification."
    };
}


/* ============================================================
   NORMALIZE CONFIDENCE
   ============================================================ */

function normalizeConfidence(
    value
) {

    let number =
        Number(value);


    if (
        !Number.isFinite(number)
    ) {

        return 0;
    }


    if (
        number > 1 &&
        number <= 100
    ) {

        number /=
            100;
    }


    return Math.max(
        0,
        Math.min(
            1,
            number
        )
    );
}


/* ============================================================
   FORMAT CONFIDENCE
   ============================================================ */

function formatConfidence(
    value
) {

    return (
        normalizeConfidence(
            value
        ) * 100
    ).toFixed(1) + "%";
}


/* ============================================================
   BUILD INDICATORS
   ============================================================ */

function buildIndicators(normalized) {

    const indicators = [];

    if (normalized.status) {
        indicators.push(`Status: ${normalized.status}`);
    }

    if (normalized.riskLevel) {
        indicators.push(`Risk level: ${normalized.riskLevel}`);
    }

    if (normalized.prediction) {
        indicators.push(`Model classification: ${normalized.prediction}`);
    }

    normalized.detectedCategories.forEach(item => {
        indicators.push(`Detected category: ${item}`);
    });

    normalized.highRiskCombinations.forEach(item => {
        indicators.push(`Risk combination: ${item}`);
    });

    normalized.indicators.forEach(item => {
        indicators.push(item);
    });

    if (normalized.riskScore !== null) {
        indicators.push(`Risk score: ${normalized.riskScore}`);
    }

    if (normalized.indicatorScore !== null) {
        indicators.push(`Indicator score: ${normalized.indicatorScore}`);
    }

    if (indicators.length === 0 && normalized.message) {
        indicators.push(normalized.message);
    }

    if (indicators.length === 0) {
        indicators.push("No additional detection indicators were returned by the engine.");
    }

    return [...new Set(indicators)].slice(0, 12);
}


function getDefaultRecommendation(riskClass, type) {

    if (riskClass === "danger") {
        if (type === "url") {
            return "Do not open the destination or enter credentials until it has been independently verified.";
        }
        if (type === "qr") {
            return "Do not open the decoded destination or provide credentials until it has been independently verified.";
        }
        return "Do not click links, share credentials, or follow instructions until the sender and request are independently verified.";
    }

    if (riskClass === "safe") {
        return "No immediate threat was indicated. Continue to use normal security precautions.";
    }

    if (type === "url") {
        return "Review the destination and sender context before opening it or entering sensitive information.";
    }

    if (type === "qr") {
        return "Review the decoded content and destination before opening it or entering sensitive information.";
    }

    return "Review the sender, links and request context before taking action.";
}


/* ============================================================
   RENDER ANALYSIS ERROR
   ============================================================ */

function renderAnalysisError(
    type,
    error
) {

    const empty =
        $(`#${type}ResultEmpty`);

    const content =
        $(`#${type}ResultContent`);

    if (empty) {

        empty.classList.add(
            "hidden"
        );
    }

    if (content) {

        content.classList.remove(
            "hidden"
        );
    }


    setResultState(
        type,
        "ERROR"
    );


    const indicator =
        $(`#${type}RiskIndicator`);

    const label =
        $(`#${type}RiskLabel`);

    const title =
        $(`#${type}ThreatTitle`);

    const description =
        $(`#${type}ThreatDescription`);


    if (indicator) {

        indicator.className =
            "risk-indicator danger";
    }


    if (label) {

        label.textContent =
            "ERROR";
    }


    if (title) {

        title.textContent =
            "Analysis could not be completed";
    }


    if (description) {

        description.textContent =
            getErrorMessage(error);
    }


    const indicators =
        $(`#${type}Indicators`);

    if (indicators) {

        indicators.innerHTML = "";

        const element =
            document.createElement(
                "div"
            );

        element.className =
            "indicator";

        element.textContent =
            "Check that the Hugging Face Space is running and that the endpoint is available.";

        indicators.appendChild(
            element
        );
    }


    const meaning =
        $(`#${type}Meaning`);

    if (meaning) {
        meaning.textContent =
            "The detection engine could not complete this analysis.";
    }

    const recommendation =
        $(`#${type}Recommendation`);

    if (recommendation) {
        recommendation.textContent =
            "Retry the analysis or verify that the detection engine is available.";
    }

    const raw =
        $(`#${type}Raw`);

    if (raw) {

        raw.textContent =
            error?.stack ||
            String(error);
    }
}


/* ============================================================
   RESET RESULT
   ============================================================ */

function resetResult(
    type
) {

    const empty =
        $(`#${type}ResultEmpty`);

    const content =
        $(`#${type}ResultContent`);

    if (empty) {

        empty.classList.remove(
            "hidden"
        );
    }

    if (content) {

        content.classList.add(
            "hidden"
        );
    }


    setResultState(
        type,
        "WAITING"
    );
}


/* ============================================================
   RAW TOGGLES
   ============================================================ */

function initializeRawToggles() {

    $$(".raw-toggle").forEach(
        button => {

            button.addEventListener(
                "click",
                () => {

                    const target =
                        $(
                            `#${button.dataset.target}`
                        );

                    if (!target) {
                        return;
                    }

                    target.classList.toggle(
                        "hidden"
                    );


                    const plus =
                        button.querySelector(
                            "span"
                        );

                    if (plus) {

                        plus.textContent =
                            target.classList.contains(
                                "hidden"
                            )
                                ? "+"
                                : "−";
                    }
                }
            );
        }
    );
}


/* ============================================================
   LOADING
   ============================================================ */

function showLoading(
    title,
    description
) {

    const overlay =
        $("#loadingOverlay");

    $("#loadingTitle").textContent =
        title;

    $("#loadingDescription").textContent =
        description;

    overlay.classList.remove(
        "hidden"
    );
}


function hideLoading() {

    $("#loadingOverlay")
        .classList.add(
            "hidden"
        );
}


/* ============================================================
   TOAST
   ============================================================ */

let toastTimer =
    null;


function showToast(
    title,
    message,
    type = "success"
) {

    const toast =
        $("#toast");

    const icon =
        $("#toastIcon");


    $("#toastTitle").textContent =
        title;

    $("#toastMessage").textContent =
        message;


    if (
        type === "error"
    ) {

        icon.textContent =
            "!";

        icon.style.color =
            "var(--red)";

        icon.style.background =
            "rgba(239, 68, 68, 0.08)";

    } else {

        icon.textContent =
            "✓";

        icon.style.color =
            "var(--green)";

        icon.style.background =
            "rgba(34, 197, 94, 0.08)";
    }


    toast.classList.add(
        "show"
    );


    clearTimeout(
        toastTimer
    );


    toastTimer =
        setTimeout(
            () => {

                toast.classList.remove(
                    "show"
                );

            },
            4500
        );
}


$("#toastClose")
    ?.addEventListener(
        "click",
        () => {

            $("#toast")
                .classList.remove(
                    "show"
                );
        }
    );


/* ============================================================
   UNIFIED INCIDENT CENTER
   ============================================================ */

const INCIDENTS_KEY = "cyberguard_unified_incidents";

function loadIncidents() {
    try {
        const saved = localStorage.getItem(INCIDENTS_KEY);
        state.incidents = saved ? JSON.parse(saved) : [];
        if (!Array.isArray(state.incidents)) state.incidents = [];
    } catch {
        state.incidents = [];
    }
    renderIncidentCenter();
}

function saveIncidents() {
    try {
        localStorage.setItem(INCIDENTS_KEY, JSON.stringify(state.incidents.slice(0, 50)));
    } catch (error) {
        console.warn("[CyberGuard] Could not save unified incidents:", error);
    }
}

function addUnifiedIncidents(incidents) {
    if (!Array.isArray(incidents) || incidents.length === 0) return;
    const existing = new Set(state.incidents.map(item => String(item.incident_id || "")));
    incidents.forEach(item => {
        if (!item || existing.has(String(item.incident_id || ""))) return;
        state.incidents.unshift(item);
        existing.add(String(item.incident_id || ""));
    });
    state.incidents = state.incidents.slice(0, 50);
    saveIncidents();
    renderIncidentCenter();
}

function buildClientIncident(module, normalized, input, target = "") {
    const risk = determineRisk(normalized);
    const score = normalized.riskScore !== null
        ? Number(normalized.riskScore)
        : risk.className === "danger" ? 80 : risk.className === "safe" ? 10 : 45;
    const severity = risk.className === "danger" ? "HIGH" : risk.className === "safe" ? "LOW" : "MEDIUM";
    const confidence = normalized.confidence !== null
        ? (Number(normalized.confidence) >= 75 ? "HIGH" : Number(normalized.confidence) >= 45 ? "MEDIUM" : "LOW")
        : "MEDIUM";
    const attackType = normalized.prediction || normalized.label || normalized.threat || "Phishing / Communication Threat";
    return {
        incident_id: `CG-PHI-${Date.now().toString(36)}`,
        timestamp: new Date().toISOString(),
        module,
        severity,
        risk_score: Math.max(0, Math.min(Math.round(score), 100)),
        confidence,
        attack_type: String(attackType),
        source: input || "reported content",
        target,
        organisation: getOrganisationProfile(),
        evidence: buildIndicators(normalized),
        recommendations: [
            "Do not click links, scan codes or provide credentials from the reported content.",
            "Verify the sender or destination through an official channel.",
            "Report suspicious content through the organisation's security process."
        ]
    };
}

function renderIncidentCenter() {
    const total = state.incidents.length;
    const high = state.incidents.filter(item => String(item.severity).toUpperCase() === "HIGH").length;
    const medium = state.incidents.filter(item => String(item.severity).toUpperCase() === "MEDIUM").length;
    const low = state.incidents.filter(item => String(item.severity).toUpperCase() === "LOW").length;

    const set = (id, value) => {
        const el = $(id);
        if (el) el.textContent = String(value);
    };
    set("#unifiedIncidentTotal", total);
    set("#unifiedIncidentHigh", high);
    set("#unifiedIncidentMedium", medium);
    set("#unifiedIncidentLow", low);

    const list = $("#unifiedIncidentList");
    if (!list) return;
    if (!state.incidents.length) {
        list.innerHTML = `<div class="unified-empty">No incidents recorded yet. Completed analyses from the three engines will appear here.</div>`;
        return;
    }
    list.innerHTML = state.incidents.slice(0, 6).map(item => {
        const severity = String(item.severity || "UNKNOWN").toUpperCase();
        const cls = severity === "HIGH" ? "high" : severity === "MEDIUM" ? "medium" : "low";
        const rawAttackType = String(item.attack_type || "").trim();
        const attackType = /^(LOW|MEDIUM|HIGH)(\s+RISK)?$/i.test(rawAttackType)
            ? "Recent Security Event"
            : (rawAttackType || "Recent Security Event");
        return `<div class="unified-incident-row ${cls}">
            <div><strong>${escapeHtml(attackType)}</strong><span>${escapeHtml(item.module || "unknown")} · ${escapeHtml(item.incident_id || "")}</span></div>
            <b>${escapeHtml(severity)}</b>
            <em>${escapeHtml(String(item.risk_score ?? 0))}</em>
        </div>`;
    }).join("");
}

/* ============================================================
   HISTORY
   ============================================================ */

function loadHistory() {

    try {

        const saved =
            localStorage.getItem(
                CONFIG.HISTORY_KEY
            );

        if (saved) {

            state.history =
                JSON.parse(
                    saved
                );
        }

    } catch (error) {

        console.warn(
            "[CyberGuard] Could not load history:",
            error
        );

        state.history =
            [];
    }


    renderHistory();
}


function saveHistory() {

    try {

        localStorage.setItem(
            CONFIG.HISTORY_KEY,
            JSON.stringify(
                state.history
            )
        );

    } catch (error) {

        console.warn(
            "[CyberGuard] Could not save history:",
            error
        );
    }
}


function addHistoryEntry(
    entry
) {

    const historyEntry = {

        id:
            Date.now(),

        type:
            entry.type ||
            "Analysis",

        input:
            entry.input ||
            "",

        result:
            entry.result ||
            "",

        severity:
            entry.severity ||
            "",

        riskScore:
            entry.riskScore ??
            null,

        incidentId:
            entry.incidentId ||
            "",

        timestamp:
            new Date().toISOString()
    };


    state.history.unshift(
        historyEntry
    );


    state.history =
        state.history.slice(
            0,
            30
        );


    saveHistory();

    renderHistory();
}


function renderHistory() {

    const container =
        $("#historyList");

    if (!container) {
        return;
    }


    if (
        state.history.length === 0
    ) {

        container.innerHTML = `

            <div class="history-empty">

                <div>◷</div>

                <h4>
                    No analysis history
                </h4>

                <p>
                    Completed analyses will appear here.
                </p>

            </div>

        `;

        return;
    }


    container.innerHTML =
        state.history
            .map(
                entry => {

                    const icon =
                        getHistoryIcon(
                            entry.type
                        );

                    const time =
                        formatDate(
                            entry.timestamp
                        );


                    return `

                        <div class="history-item">

                            <div class="history-type">
                                ${icon}
                            </div>

                            <div class="history-main">

                                <strong>
                                    ${escapeHtml(
                                        entry.type
                                    )}
                                </strong>

                                <p>
                                    ${escapeHtml(
                                        truncate(
                                            entry.input,
                                            100
                                        )
                                    )}
                                </p>

                                <div class="history-meta">
                                    ${entry.severity ? `<span class="history-severity ${String(entry.severity).toLowerCase()}">${escapeHtml(entry.severity)}</span>` : ""}
                                    ${entry.riskScore != null ? `<span>Risk ${escapeHtml(entry.riskScore)}</span>` : ""}
                                    ${entry.incidentId ? `<span>${escapeHtml(entry.incidentId)}</span>` : ""}
                                </div>

                            </div>

                            <div class="history-time">
                                ${escapeHtml(time)}
                            </div>

                        </div>

                    `;
                }
            )
            .join("");
}


function getHistoryIcon(
    type
) {

    const icons = {

        Message:
            "✉",

        URL:
            "↗",

        Website:
            "◫",

        "QR Code":
            "▦"
    };


    return (
        icons[type] ||
        "⌁"
    );
}


function formatDate(
    timestamp
) {

    try {

        return new Date(
            timestamp
        ).toLocaleString(
            [],
            {
                day: "2-digit",
                month: "short",
                hour: "2-digit",
                minute: "2-digit"
            }
        );

    } catch {

        return "Unknown";
    }
}


/* ============================================================
   CLEAR HISTORY
   ============================================================ */

const clearHistoryButton =
    $("#clearHistoryButton");

if (clearHistoryButton) {

    clearHistoryButton.addEventListener(
        "click",
        () => {

            if (
                state.history.length === 0
            ) {

                showToast(
                    "Nothing to clear",
                    "There is no analysis history.",
                    "error"
                );

                return;
            }


            state.history =
                [];

            saveHistory();

            renderHistory();


            showToast(
                "History cleared",
                "Analysis history has been removed from this browser.",
                "success"
            );
        }
    );
}


/* ============================================================
   ORGANISATION SETTINGS
   ============================================================ */

function organisationSlug(name) {

    return (
        String(name || "")
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, "-")
            .replace(/^-+|-+$/g, "")
    ) || "organisation";
}


function normaliseOrganisationDomain(value) {

    return String(value || "")
        .trim()
        .toLowerCase()
        .replace(/^https?:\/\//, "")
        .replace(/\/.*$/, "");
}


function isValidOrganisationDomain(value) {

    return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(
        value
    );
}


/* The organisation profile drives every organisation-specific sample
   in the dashboard (currently the Digital Impersonation demo data):
   the configured name and email domain, or a derived domain when none
   is configured. */

function getOrganisationProfile() {

    const name =
        (state.organisation || "").trim() ||
        "Acme Corporation";

    const configured =
        normaliseOrganisationDomain(
            state.organisationDomain
        );

    const domain = isValidOrganisationDomain(configured)
        ? configured
        : `${organisationSlug(name)}.com`;

    return { name, domain };
}


function initializeOrganisationSettings() {

    const saveButton =
        $("#saveOrganisationButton");

    const input =
        $("#organisationInput");

    const domainInput =
        $("#organisationDomainInput");


    if (
        !saveButton ||
        !input
    ) {

        return;
    }


    input.value =
        state.organisation;

    if (domainInput) {

        domainInput.value =
            state.organisationDomain;
    }


    saveButton.addEventListener(
        "click",
        () => {

            const value =
                input.value.trim();

            const domain = normaliseOrganisationDomain(
                domainInput ? domainInput.value : ""
            );


            if (!value) {

                showToast(
                    "Organisation name required",
                    "Enter an organisation name first.",
                    "error"
                );

                return;
            }


            if (
                domain &&
                !isValidOrganisationDomain(domain)
            ) {

                showToast(
                    "Invalid organisation domain",
                    "Enter a domain such as acme-corp.com, or leave it blank to derive one from the name.",
                    "error"
                );

                return;
            }


            state.organisation =
                value;

            state.organisationDomain =
                domain;


            try {

                localStorage.setItem(
                    CONFIG.ORGANISATION_KEY,
                    value
                );

                localStorage.setItem(
                    CONFIG.ORGANISATION_DOMAIN_KEY,
                    domain
                );

            } catch (error) {

                console.warn(
                    "[CyberGuard] Organisation could not be saved:",
                    error
                );
            }


            updateOrganisationUI();


            showToast(
                "Organisation updated",
                `Sample data now uses ${getOrganisationProfile().name} (${getOrganisationProfile().domain}).`,
                "success"
            );
        }
    );
}


function loadOrganisation() {

    try {

        const saved =
            localStorage.getItem(
                CONFIG.ORGANISATION_KEY
            );

        if (
            saved &&
            saved.trim()
        ) {

            state.organisation =
                saved.trim();
        }

        const savedDomain =
            localStorage.getItem(
                CONFIG.ORGANISATION_DOMAIN_KEY
            );

        if (savedDomain !== null) {

            state.organisationDomain =
                savedDomain.trim();
        }

    } catch (error) {

        console.warn(
            "[CyberGuard] Could not load organisation:",
            error
        );
    }
}


function updateOrganisationUI() {

    const topName =
        $("#topOrganisationName");

    const displayName =
        $("#organisationDisplayName");

    const input =
        $("#organisationInput");

    const domainInput =
        $("#organisationDomainInput");


    if (topName) {

        topName.textContent =
            state.organisation;
    }


    if (displayName) {

        displayName.textContent =
            state.organisation;
    }


    if (
        input &&
        document.activeElement !== input
    ) {

        input.value =
            state.organisation;
    }


    if (
        domainInput &&
        document.activeElement !== domainInput
    ) {

        domainInput.value =
            state.organisationDomain;
    }
}


/* ============================================================
   UTILITY FUNCTIONS
   ============================================================ */

function safePrettyPrint(
    value
) {

    try {

        return JSON.stringify(
            value,
            null,
            2
        );

    } catch {

        return String(value);
    }
}


function summarizeResult(
    value
) {

    const normalized =
        normalizeResult(
            value
        );


    if (
        normalized.label
    ) {

        return normalized.label;
    }


    if (
        normalized.message
    ) {

        return truncate(
            normalized.message,
            100
        );
    }


    return "Analysis completed";
}


function truncate(
    value,
    length
) {

    const string =
        String(
            value ||
            ""
        );


    if (
        string.length <=
        length
    ) {

        return string;
    }


    return (
        string.slice(
            0,
            length - 1
        ) +
        "…"
    );
}


function formatFileSize(
    bytes
) {

    if (
        bytes <
        1024
    ) {

        return `${bytes} B`;
    }


    if (
        bytes <
        1024 * 1024
    ) {

        return `${(
            bytes /
            1024
        ).toFixed(1)} KB`;
    }


    return `${(
        bytes /
        (1024 * 1024)
    ).toFixed(1)} MB`;
}


function escapeHtml(
    value
) {

    return String(
        value ||
        ""
    )
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );
}


/* ============================================================
   ERROR MESSAGE
   ============================================================ */

function getErrorMessage(
    error
) {

    if (
        error &&
        typeof error.message ===
        "string"
    ) {

        return error.message;
    }


    return (
        "The detection engine returned an unexpected error."
    );
}


/* ============================================================
   MESSAGE TYPE DISPLAY
   ============================================================ */

const messageType =
    $("#messageType");

if (messageType) {

    messageType.addEventListener(
        "change",
        () => {

            const textarea =
                $("#messageInput");

            if (!textarea) {
                return;
            }


            const type =
                messageType.value;


            const placeholders = {

                "Email":
                    "Paste the suspicious email content here...",

                "SMS / Message":
                    "Paste the suspicious SMS or message here...",

                "Social Media":
                    "Paste the suspicious social-media message here..."
            };


            textarea.placeholder =
                placeholders[type] ||
                "Paste suspicious content here...";
        }
    );
}


/* ============================================================
   KEYBOARD SHORTCUT
   ============================================================ */

document.addEventListener(
    "keydown",
    event => {

        /*
         * Ctrl + K focuses the main phishing input.
         */

        if (
            event.ctrlKey &&
            event.key.toLowerCase() === "k"
        ) {

            event.preventDefault();

            navigateTo("phishing");

            activateAnalysis("message");

            $("#messageInput")
                ?.focus();
        }
    }
);


/* ============================================================
   DEVELOPMENT LOG
   ============================================================ */

console.log(
    "%cCYBERGUARD",
    "font-size:20px;font-weight:800;color:#60a5fa;"
);

console.log(
    "%cOrganisation Security Platform",
    "font-size:11px;color:#94a3b8;"
);

console.log(
    "[CyberGuard] Frontend initialized."
);

console.log(
    "[CyberGuard] Hugging Face Space:",
    CONFIG.HF_SPACE
);

console.log(
    "[CyberGuard] Endpoints:",
    CONFIG.ENDPOINTS
);
