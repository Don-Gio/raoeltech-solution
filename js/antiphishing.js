/**
 * Moteur d'analyse Anti-Phishing Corrigé & Optimisé — RaoelTech Solutions
 */

let globalThreatDatabase = {
    maliciousDomains: new Set(), // Utilisation d'un Set pour des recherches ultra-rapides O(1)
    loaded: false
};

// Chargement d'une base de données de menaces propre (format domaine)
async function loadProfessionalThreatFeed() {
    try {
        // Utilisation d'un flux de domaines malveillants open-source standard
        const response = await fetch('https://raw.githubusercontent.com/mitmproxy/proxy2/master/phishing_list.json');
        if (response.ok) {
            const data = await response.json();
            // Alimentation du Set avec les domaines
            if (Array.isArray(data)) {
                data.forEach(domain => globalThreatDatabase.maliciousDomains.add(domain.toLowerCase()));
            }
            globalThreatDatabase.loaded = true;
            console.log("Base de données de menaces synchronisée avec succès.");
        }
    } catch (e) {
        console.warn("Mode heuristique autonome actif (Impossible de joindre le flux distant).");
    }
}

document.addEventListener("DOMContentLoaded", () => {
    loadProfessionalThreatFeed();

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

function analyzeURL(rawUrl) {
    let score = 0;
    const flags = [];

    let cleanUrl = rawUrl;
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
        cleanUrl = 'https://' + cleanUrl;
    }

    try {
        const parsedUrl = new URL(cleanUrl);
        const hostname = parsedUrl.hostname.toLowerCase();
        const fullString = parsedUrl.href;
        const tld = hostname.split('.').pop();

        // 1. Correction : Vérification sécurisée dans la base de menaces globale
        if (globalThreatDatabase.loaded && globalThreatDatabase.maliciousDomains.has(hostname)) {
            score += 100;
            flags.push("ALERTE ROUGE : Ce domaine est répertorié dans la base de données internationale des sites de phishing.");
        }

        // 2. Caractère '@' (Userinfo bypass)
        if (cleanUrl.includes('@')) {
            score += 50;
            flags.push("Critique : Présence du caractère '@' utilisé pour masquer la véritable destination.");
        }

        // 3. Adresse IP brute
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
            score += 45;
            flags.push("Alerte : Utilisation d'une adresse IP brute au lieu d'un nom de domaine qualifié.");
        }

        // 4. Entropie (Botnet / DGA)
        const domainWithoutExt = hostname.split('.').slice(0, -1).join('');
        const entropy = calculateEntropy(domainWithoutExt);
        if (entropy > 3.8 && domainWithoutExt.length > 6) {
            score += 35;
            flags.push(`Alerte Entropie : Nom de domaine hautement aléatoire (Score: ${entropy.toFixed(2)}), caractéristique d'un générateur de botnet.`);
        }

        // 5. Typosquatting (Marques internationales et locales)
        const targetBrands = ["airtel", "telma", "orange", "bni", "bmoi", "google", "microsoft", "facebook", "paypal", "netflix"];
        targetBrands.forEach(brand => {
            if (hostname.includes(brand) && !hostname.endsWith(`${brand}.mg`) && !hostname.endsWith(`${brand}.com`) && !hostname.endsWith(`www.${brand}.com`)) {
                score += 40;
                flags.push(`Alerte Typosquatting : Le domaine détourne la marque protégée "${brand}".`);
            }
        });

        // 6. Mots-clés sensibles
        const sensitiveKeywords = ['login', 'signin', 'verify', 'update', 'banking', 'secure', 'account', 'password', 'confirm', 'support', 'wallet', 'kyc'];
        const matches = sensitiveKeywords.filter(kw => fullString.toLowerCase().includes(kw));
        if (matches.length > 0) {
            score += 30;
            flags.push(`Indice : Présence de termes sensibles à haut risque (${matches.join(', ')}).`);
        }

        let riskLevel = "SÛR";
        let badgeClass = "bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-900/30 dark:text-emerald-400 dark:border-emerald-800";
        const finalScore = Math.min(score, 100);

        if (finalScore >= 50) {
            riskLevel = "HAUTEMENT DANGEREUX";
            badgeClass = "bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-900/30 dark:text-rose-400 dark:border-rose-800";
        } else if (finalScore >= 20) {
            riskLevel = "SUSPECT / VIGILANCE";
            badgeClass = "bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-900/30 dark:text-amber-400 dark:border-amber-800";
        }

        return { hostname, score: finalScore, riskLevel, badgeClass, flags };

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