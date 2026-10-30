/**
 * Moteur d'analyse Anti-Phishing Avancé — RaoelTech Solutions
 * Matrice de mots-clés et heuristique de pointe
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
                li.textContent = "✔ Aucun indicateur suspect ni motif de phishing détecté.";
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
        const fullString = parsedUrl.href.toLowerCase();
        const tld = hostname.split('.').pop();

        // 1. Contournement Userinfo ('@')
        if (cleanUrl.includes('@')) {
            score += 50;
            flags.push("Critique : Présence du caractère '@' utilisé pour masquer la véritable destination.");
        }

        // 2. Adresse IP brute
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
            score += 45;
            flags.push("Alerte : Utilisation d'une adresse IP brute à la place d'un domaine qualifié.");
        }

        // 3. Extensions (TLD) à haut risque
        const highRiskTlds = ['top', 'xyz', 'buzz', 'click', 'tk', 'gq', 'ml', 'cf', 'ga', 'fit', 'work', 'loan', 'surf', 'icu', 'su'];
        if (highRiskTlds.includes(tld)) {
            score += 25;
            flags.push(`Alerte TLD : Extension de domaine hautement suspecte (.${tld}).`);
        }

        // 4. Profondeur excessive des sous-domaines
        if (hostname.split('.').length > 4) {
            score += 30;
            flags.push("Alerte : Profondeur anormale de sous-domaines (technique d'usurpation visuelle).");
        }

        // 5. Entropie (Domaine généré par algorithme / Botnet)
        const domainWithoutExt = hostname.split('.').slice(0, -1).join('');
        const entropy = calculateEntropy(domainWithoutExt);
        if (entropy > 3.8 && domainWithoutExt.length > 6) {
            score += 35;
            flags.push(`Alerte Entropie : Nom de domaine aléatoire (Score: ${entropy.toFixed(2)}), typique d'une génération par botnet.`);
        }

        // 6. MATRICE DE MOTS-CLÉS PROFESSIONNELLE & SCÉNARIOS D'ATTAQUE
        
        // A. Urgence et incitation à l'action frauduleuse
        const urgencyKeywords = ['urgent', 'suspended', 'locked', 'blocked', 'expired', 'alert', 'action-required', 'security-check', 'reactivate'];
        const matchedUrgency = urgencyKeywords.filter(kw => fullString.includes(kw));
        if (matchedUrgency.length > 0) {
            score += 30;
            flags.push(`Indice Social Engineering : Termes d'urgence ou de menace (${matchedUrgency.join(', ')}).`);
        }

        // B. Authentification, Comptes & KYC
        const authKeywords = ['login', 'signin', 'auth', 'verify', 'update', 'account', 'password', 'credential', 'identity', 'customer', 'portal', 'kyc'];
        const matchedAuth = authKeywords.filter(kw => fullString.includes(kw));
        if (matchedAuth.length > 0) {
            score += 25;
            flags.push(`Indice : Mots-clés de compromission de compte/connexion (${matchedAuth.join(', ')}).`);
        }

        // C. Financier & Mobile Money (Global + Spécificités Madagascar)
        const financialKeywords = ['banking', 'secure', 'wallet', 'payment', 'invoice', 'billing', 'mvola', 'orange-money', 'airtel-money', 'rib', 'transfer'];
        const matchedFinancial = financialKeywords.filter(kw => fullString.includes(kw));
        if (matchedFinancial.length > 0) {
            score += 35;
            flags.push(`Alerte Financière : Termes liés aux paiements ou au Mobile Money (${matchedFinancial.join(', ')}).`);
        }

        // 7. Typosquatting (Marques Internationales & Locales Madagascar)
        const targetBrands = [
            // International
            "google", "microsoft", "facebook", "paypal", "netflix", "apple", "amazon", "instagram", "whatsapp", "binance",
            // Local Madagascar (Opérateurs & Banques)
            "airtel", "telma", "orange", "bni", "bmoi", "cbao", "societegenerale", "boa", "jirama", "cnaps"
        ];
        
        targetBrands.forEach(brand => {
            if (hostname.includes(brand) && !hostname.endsWith(`${brand}.mg`) && !hostname.endsWith(`${brand}.com`) && !hostname.endsWith(`www.${brand}.com`) && !hostname.endsWith(`${brand}.fr`)) {
                score += 40;
                flags.push(`Alerte Typosquatting : Le domaine détourne ou imite la marque protégée "${brand}".`);
            }
        });

        // Calcul du score final
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