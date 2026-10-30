/**
 * Moteur d'analyse Anti-Phishing Avancé — RaoelTech Solutions
 * Version Pro : Heuristique + Entropie + Typosquatting
 */

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("phishing-form");
    const inputUrl = document.getElementById("url-input");
    const resultsContainer = document.getElementById("phishing-results");
    const analyzedDomain = document.getElementById("analyzed-domain");
    const riskBadge = document.getElementById("risk-badge");
    const heuristicsList = document.getElementById("heuristics-list");
    
    const linkVirustotal = document.getElementById("link-virustotal");
    const linkUrlscan = document.getElementById("link-urlscan");
    const linkGoogleSafebrowsing = document.getElementById("link-google-safebrowsing");

    if (form && inputUrl) {
        form.addEventListener("submit", (e) => {
            e.preventDefault();
            const rawUrl = inputUrl.value.trim();
            if (!rawUrl) return;

            const analysis = analyzeURL(rawUrl);

            resultsContainer.classList.remove("hidden");
            analyzedDomain.textContent = analysis.hostname;

            riskBadge.textContent = analysis.riskLevel;
            riskBadge.className = `text-xs px-3 py-1 rounded-full font-bold border ${analysis.badgeClass}`;

            heuristicsList.innerHTML = "";
            if (analysis.flags.length === 0) {
                const li = document.createElement("li");
                li.textContent = "✔ Aucun indicateur suspect détecté dans la structure de l'URL.";
                li.className = "text-emerald-600 dark:text-emerald-400 font-medium";
                heuristicsList.appendChild(li);
            } else {
                analysis.flags.forEach(flag => {
                    const li = document.createElement("li");
                    li.textContent = `• ${flag}`;
                    li.className = "text-rose-600 dark:text-rose-400 font-medium my-1";
                    heuristicsList.appendChild(li);
                });
            }

            if (linkVirustotal) linkVirustotal.href = `https://www.virustotal.com/gui/search/${encodeURIComponent(rawUrl)}`;
            if (linkUrlscan) linkUrlscan.href = `https://urlscan.io/search/#${encodeURIComponent(rawUrl)}`;
            if (linkGoogleSafebrowsing) linkGoogleSafebrowsing.href = `https://transparencyreport.google.com/safe-browsing-search?url=${encodeURIComponent(rawUrl)}`;

            resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        });
    }
});

/**
 * Calcul de l'entropie de Shannon d'une chaîne de caractères
 * Permet de mesurer le degré d'aléatoire d'un nom de domaine (DGA detection)
 */
function calculateEntropy(str) {
    const len = str.length;
    if (len === 0) return 0;
    const frequencies = {};
    for (let char of str) {
        frequencies[char] = (frequencies[char] || 0) + 1;
    }
    return Object.values(frequencies).reduce((sum, freq) => {
        const p = freq / len;
        return sum - p * Math.log2(p);
    }, 0);
}

/**
 * Algorithme heuristique étendu (Entropie + Typosquatting + Règles de base)
 */
function analyzeURL(rawUrl) {
    let score = 0;
    const flags = [];

    let cleanUrl = rawUrl;
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
        cleanUrl = 'https://' + cleanUrl;
    }

    try {
        const parsedUrl = new URL(cleanUrl);
        const hostname = parsedUrl.hostname;
        const fullString = parsedUrl.href;

        // 1. Caractère '@' (Userinfo bypass)
        if (cleanUrl.includes('@')) {
            score += 45;
            flags.push("Critique : Présence du caractère '@' utilisé pour masquer la véritable destination.");
        }

        // 2. Adresse IP brute
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
            score += 40;
            flags.push("Alerte : Utilisation d'une adresse IP brute au lieu d'un nom de domaine qualifié.");
        }

        // 3. Profondeur des sous-domaines
        if (hostname.split('.').length > 4) {
            score += 30;
            flags.push("Alerte : Profondeur de sous-domaines suspecte (risque d'usurpation visuelle).");
        }

        // 4. Attaque Punycode (IDN)
        if (hostname.startsWith('xn--')) {
            score += 35;
            flags.push("Risque élevé : Domaine encodé en Punycode (imitation potentielle de marque).");
        }

        // 5. Analyse de l'Entropie (Domaine généré par algorithme / Botnet)
        const domainWithoutExt = hostname.split('.')[0];
        const entropy = calculateEntropy(domainWithoutExt);
        if (entropy > 4.2 && domainWithoutExt.length > 8) {
            score += 30;
            flags.push(`Alerte Entropie : Nom de domaine hautement aléatoire (Score: ${entropy.toFixed(2)}), typique d'un générateur malveillant.`);
        }

        // 6. Détection de Typosquatting (Marques protégées et services locaux/internationaux)
        const targetBrands = ["google", "microsoft", "facebook", "paypal", "netflix", "airtel", "telma", "orange", "bank"];
        targetBrands.forEach(brand => {
            if (hostname.includes(brand) && hostname !== `${brand}.com` && hostname !== `www.${brand}.com` && !hostname.endsWith(`.${brand}.mg`)) {
                score += 35;
                flags.push(`Alerte Typosquatting : Le nom de domaine imite ou détourne la marque protégée "${brand}".`);
            }
        });

        // 7. Mots-clés sensibles
        const sensitiveKeywords = ['login', 'signin', 'verify', 'update', 'banking', 'secure', 'account', 'password', 'confirm', 'support', 'wallet', 'kyc'];
        const matches = sensitiveKeywords.filter(kw => fullString.toLowerCase().includes(kw));
        if (matches.length > 0) {
            score += 25;
            flags.push(`Indice : Présence de termes sensibles à haut risque (${matches.join(', ')}).`);
        }

        // Score final
        let riskLevel = "SÛR";
        let badgeClass = "bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-900/30 dark:text-emerald-400 dark:border-emerald-800";

        if (score >= 60) {
            riskLevel = "HAUTEMENT DANGEREUX";
            badgeClass = "bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-900/30 dark:text-rose-400 dark:border-rose-800";
        } else if (score >= 30) {
            riskLevel = "SUSPECT / VIGILANCE";
            badgeClass = "bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-900/30 dark:text-amber-400 dark:border-amber-800";
        }

        return {
            hostname,
            score: Math.min(score, 100),
            riskLevel,
            badgeClass,
            flags
        };

    } catch (e) {
        return {
            hostname: rawUrl,
            score: 100,
            riskLevel: "URL INVALIDE",
            badgeClass: "bg-slate-100 text-slate-800 border-slate-300 dark:bg-slate-800 dark:text-slate-300",
            flags: ["Erreur : Format d'URL malformé ou syntaxe incorrecte."]
        };
    }
}