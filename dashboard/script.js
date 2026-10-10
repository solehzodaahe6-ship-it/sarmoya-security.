const urlInput =
    document.getElementById("urlInput");

const checkButton =
    document.getElementById("checkButton");

const resultBox =
    document.getElementById("result");

const totalBlocked =
    document.getElementById("totalBlocked");

const phishingCount =
    document.getElementById("phishingCount");

const malwareCount =
    document.getElementById("malwareCount");

const adultCount =
    document.getElementById("adultCount");

const phishingCard =
    document.getElementById("phishingCard");

const malwareCard =
    document.getElementById("malwareCard");

const eventsTable =
    document.getElementById("eventsTable");

const refreshButton =
    document.getElementById("refreshButton");

const refreshRules =
    document.getElementById("refreshRules");

const ruleForm =
    document.getElementById("ruleForm");

const ruleDomain =
    document.getElementById("ruleDomain");

const ruleAction =
    document.getElementById("ruleAction");

const ruleCategory =
    document.getElementById("ruleCategory");

const ruleMessage =
    document.getElementById("ruleMessage");

const rulesList =
    document.getElementById("rulesList");

const menuButton =
    document.getElementById("menuButton");

const sidebar =
    document.getElementById("sidebar");

const sidebarOverlay =
    document.getElementById("sidebarOverlay");


/* =========================================================
   HELPERS
========================================================= */

function escapeHtml(value) {

    const div =
        document.createElement("div");

    div.textContent =
        String(value);

    return div.innerHTML;
}


function formatCategory(category) {

    const labels = {

        phishing: "PHISHING",

        malware: "MALWARE",

        adult: "ADULT",

        scam: "SCAM",

        parent_block: "PARENT BLOCK",

        custom: "CUSTOM",

        safe: "SAFE",

        allowed_by_parent: "ALLOWED",

        invalid: "INVALID"

    };

    return labels[category] || category.toUpperCase();
}


/* =========================================================
   URL SCANNER
========================================================= */

function showResult(data) {

    resultBox.classList.remove(
        "hidden",
        "scan-safe",
        "scan-danger",
        "scan-invalid"
    );


    if (data.category === "invalid") {

        resultBox.classList.add(
            "scan-invalid"
        );


        resultBox.innerHTML = `
            <strong>⚠️ URL нодуруст аст</strong>
            <br>
            <span>
                ${escapeHtml(data.message)}
            </span>
        `;

        return;
    }


    if (data.blocked) {

        resultBox.classList.add(
            "scan-danger"
        );


        resultBox.innerHTML = `
            <div style="font-size:10px;letter-spacing:.12em;font-weight:900;">
                THREAT DETECTED
            </div>

            <div style="margin-top:8px;font-size:18px;font-weight:800;">
                🚫 Сайт баста шуд
            </div>

            <div style="margin-top:9px;font-family:monospace;font-size:11px;">
                ${escapeHtml(data.domain)}
            </div>

            <div style="margin-top:8px;font-size:10px;color:inherit;opacity:.8;">
                Category:
                ${escapeHtml(formatCategory(data.category))}
            </div>

            <div style="margin-top:10px;font-size:11px;line-height:1.6;">
                ${escapeHtml(data.message)}
            </div>
        `;

        return;
    }


    resultBox.classList.add(
        "scan-safe"
    );


    resultBox.innerHTML = `
        <div style="font-size:10px;letter-spacing:.12em;font-weight:900;">
            SECURITY CHECK PASSED
        </div>

        <div style="margin-top:8px;font-size:18px;font-weight:800;">
            ✅ Сайт иҷозат дода шуд
        </div>

        <div style="margin-top:9px;font-family:monospace;font-size:11px;">
            ${escapeHtml(data.domain)}
        </div>

        <div style="margin-top:9px;font-size:11px;">
            ${escapeHtml(data.message)}
        </div>
    `;
}


async function checkUrl(domainOverride = null) {

    const domain =
        (
            domainOverride ||
            urlInput.value
        ).trim();


    if (!domain) {

        showResult({
            category: "invalid",
            message:
                "Лутфан domain ё URL ворид кунед."
        });

        return;
    }


    checkButton.disabled = true;

    checkButton.innerHTML =
        "SCANNING...";


    try {

        const response =
            await fetch(
                "/api/check-url",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        domain: domain
                    })
                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.detail ||
                "API error"
            );
        }


        showResult(data);

        await Promise.all([
            loadStats(),
            loadEvents(),
            loadRules()
        ]);


    } catch (error) {

        resultBox.className =
            "scan-result scan-danger";

        resultBox.innerHTML = `
            <strong>❌ Пайвастшавӣ ноком шуд</strong>
            <br>
            <span>
                ${escapeHtml(error.message)}
            </span>
        `;

        console.error(error);


    } finally {

        checkButton.disabled = false;

        checkButton.innerHTML =
            'CHECK <span>↗</span>';

    }
}


/* =========================================================
   STATS
========================================================= */

async function loadStats() {

    try {

        const response =
            await fetch(
                "/api/stats"
            );


        const data =
            await response.json();


        const total =
            data.total_blocked || 0;


        const phishing =
            data.by_category?.phishing || 0;


        const malware =
            data.by_category?.malware || 0;


        const adult =
            data.by_category?.adult || 0;


        const scam =
            data.by_category?.scam || 0;


        totalBlocked.textContent =
            total;


        phishingCount.textContent =
            phishing;


        malwareCount.textContent =
            malware;


        adultCount.textContent =
            adult + scam;


        phishingCard.textContent =
            phishing;


        malwareCard.textContent =
            malware;


    } catch (error) {

        console.error(
            "Stats error:",
            error
        );

    }
}


/* =========================================================
   EVENTS
========================================================= */

async function loadEvents() {

    try {

        const response =
            await fetch(
                "/api/blocked"
            );


        const data =
            await response.json();


        const events =
            data.events || [];


        if (!events.length) {

            eventsTable.innerHTML = `
                <div class="empty-activity">

                    <div class="empty-icon">
                        ◌
                    </div>

                    <strong>
                        Ҳоло event нест
                    </strong>

                    <span>
                        Натиҷаҳои санҷиш дар ин ҷо пайдо мешаванд.
                    </span>

                </div>
            `;

            return;
        }


        eventsTable.innerHTML =
            events.map(
                (event) => {

                    const category =
                        formatCategory(
                            event.category
                        );


                    return `
                        <div class="activity-item">

                            <div class="activity-icon danger">
                                ×
                            </div>


                            <div class="activity-main">

                                <strong>
                                    ${escapeHtml(event.domain)}
                                </strong>

                                <span>
                                    ${escapeHtml(category)}
                                </span>

                            </div>


                            <div class="activity-meta">

                                <span>
                                    BLOCKED
                                </span>

                                <time>
                                    ${escapeHtml(
                                        event.created_at
                                    )}
                                </time>

                            </div>

                        </div>
                    `;

                }
            ).join("");


    } catch (error) {

        console.error(
            "Events error:",
            error
        );

    }
}


/* =========================================================
   RULES
========================================================= */

async function loadRules() {

    try {

        const response =
            await fetch(
                "/api/rules"
            );


        const data =
            await response.json();


        const rules =
            data.rules || [];


        if (!rules.length) {

            rulesList.innerHTML = `
                <div class="empty-rule">
                    Ҳоло қоидае вуҷуд надорад.
                </div>
            `;

            return;
        }


        rulesList.innerHTML =
            rules.map(
                (rule) => {

                    const isBlock =
                        rule.action === "BLOCK";


                    return `
                        <div class="rule-item">

                            <div class="rule-item-top">

                                <div class="rule-domain">
                                    ${escapeHtml(
                                        rule.domain
                                    )}
                                </div>


                                <span
                                    class="rule-action ${
                                        isBlock
                                            ? "rule-block"
                                            : "rule-allow"
                                    }"
                                >
                                    ${
                                        isBlock
                                            ? "BLOCK"
                                            : "ALLOW"
                                    }
                                </span>

                            </div>


                            <div class="rule-item-bottom">

                                <span>
                                    ${escapeHtml(
                                        rule.category
                                    )}
                                </span>


                                <button
                                    class="delete-rule"
                                    onclick="deleteRule(${rule.id})"
                                >
                                    Нест кардан
                                </button>

                            </div>

                        </div>
                    `;
                }
            ).join("");


    } catch (error) {

        rulesList.innerHTML = `
            <div class="empty-rule">
                Қоидаҳоро бор кардан имконнопазир аст.
            </div>
        `;

        console.error(
            "Rules error:",
            error
        );
    }
}


/* =========================================================
   CREATE RULE
========================================================= */

ruleForm.addEventListener(
    "submit",
    async (event) => {

        event.preventDefault();


        const domain =
            ruleDomain.value.trim();


        if (!domain) {

            showRuleMessage(
                "Domain ворид кунед.",
                false
            );

            return;
        }


        try {

            const response =
                await fetch(
                    "/api/rules",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            domain: domain,

                            action:
                                ruleAction.value,

                            category:
                                ruleCategory.value
                        })
                    }
                );


            const data =
                await response.json();


            if (!response.ok) {

                throw new Error(
                    data.detail ||
                    data.message ||
                    "Хатои сервер"
                );
            }


            if (data.success === false) {

                throw new Error(
                    data.message
                );
            }


            showRuleMessage(
                `Қоида барои ${data.domain} захира шуд.`,
                true
            );


            ruleForm.reset();


            await loadRules();


        } catch (error) {

            showRuleMessage(
                error.message,
                false
            );

        }

    }
);


function showRuleMessage(
    message,
    success
) {

    ruleMessage.classList.remove(
        "hidden"
    );


    ruleMessage.style.background =
        success
            ? "rgba(80,242,161,.06)"
            : "rgba(255,101,122,.06)";


    ruleMessage.style.border =
        success
            ? "1px solid rgba(80,242,161,.13)"
            : "1px solid rgba(255,101,122,.13)";


    ruleMessage.style.color =
        success
            ? "#8de2b2"
            : "#ff9eaa";


    ruleMessage.textContent =
        message;

}


/* =========================================================
   DELETE RULE
========================================================= */

async function deleteRule(id) {

    try {

        const response =
            await fetch(
                `/api/rules/${id}`,
                {
                    method: "DELETE"
                }
            );


        if (!response.ok) {

            throw new Error(
                "Нест кардан имконнопазир аст."
            );
        }


        await loadRules();


    } catch (error) {

        showRuleMessage(
            error.message,
            false
        );

    }
}


/* =========================================================
   QUICK TESTS
========================================================= */

document
    .querySelectorAll(".quick-test")
    .forEach(
        (button) => {

            button.addEventListener(
                "click",
                () => {

                    const domain =
                        button.dataset.domain;


                    urlInput.value =
                        domain;


                    checkUrl(
                        domain
                    );

                }
            );

        }
    );


/* =========================================================
   REFRESH
========================================================= */

refreshButton.addEventListener(
    "click",
    async () => {

        refreshButton.style.transform =
            "rotate(360deg)";

        await Promise.all([
            loadStats(),
            loadEvents(),
            loadRules()
        ]);

        setTimeout(
            () => {
                refreshButton.style.transform =
                    "";
            },
            300
        );

    }
);


refreshRules.addEventListener(
    "click",
    async () => {

        await loadRules();

    }
);


/* =========================================================
   ENTER KEY
========================================================= */

urlInput.addEventListener(
    "keydown",
    (event) => {

        if (event.key === "Enter") {
            checkUrl();
        }

    }
);


/* =========================================================
   MOBILE SIDEBAR
========================================================= */

function closeSidebar() {

    sidebar.classList.remove(
        "open"
    );

    sidebarOverlay.classList.remove(
        "open"
    );

}


function toggleSidebar() {

    sidebar.classList.toggle(
        "open"
    );

    sidebarOverlay.classList.toggle(
        "open"
    );

}


menuButton.addEventListener(
    "click",
    toggleSidebar
);


sidebarOverlay.addEventListener(
    "click",
    closeSidebar
);


document
    .querySelectorAll(".nav-item")
    .forEach(
        (item) => {

            item.addEventListener(
                "click",
                closeSidebar
            );

        }
    );


/* =========================================================
   TELEGRAM BUTTON
========================================================= */

const telegramButton =
    document.getElementById("telegramButton");

telegramButton.addEventListener("click", () => {
    window.open(
        "https://t.me/Sarmoya_Security_bot",
        "_blank"
    );
});

/* =========================================================
   GAME
========================================================= */

const gameButton =
    document.getElementById(
        "gameButton"
    );


const startGame =
    document.getElementById(
        "startGame"
    );


function openGameMessage() {

    alert(
        "Бозии «Фиреб ё бехатар?» дар версияи навбатӣ фаъол мешавад."
    );

}


gameButton.addEventListener(
    "click",
    openGameMessage
);


startGame.addEventListener(
    "click",
    openGameMessage
);


/* =========================================================
   ACTIVE NAV
========================================================= */

const navItems =
    document.querySelectorAll(
        ".nav-item"
    );


navItems.forEach(
    (item) => {

        item.addEventListener(
            "click",
            () => {

                navItems.forEach(
                    (nav) => {
                        nav.classList.remove(
                            "active"
                        );
                    }
                );


                item.classList.add(
                    "active"
                );

            }
        );

    }
);


/* =========================================================
   INITIAL LOAD
========================================================= */

loadStats();

loadEvents();

loadRules();