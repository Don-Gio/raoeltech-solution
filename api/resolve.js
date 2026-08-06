export default async function handler(req, res) {
    const { url } = req.query;

    if (!url) {
        return res.status(400).json({ error: "Paramètre URL manquant" });
    }

    let targetUrl = url;
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
        targetUrl = 'https://' + targetUrl;
    }

    try {
        // Suivi des redirections (bit.ly, tinyurl, etc.)
        const response = await fetch(targetUrl, { 
            method: 'HEAD', 
            redirect: 'follow',
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) RaoelTech-Scanner/1.0'
            }
        });

        return res.status(200).json({ 
            originalUrl: url,
            resolvedUrl: response.url 
        });
    } catch (error) {
        // Fallback en cas de blocage HEAD : tentative en GET
        try {
            const responseGet = await fetch(targetUrl, { 
                method: 'GET', 
                redirect: 'follow',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) RaoelTech-Scanner/1.0'
                }
            });
            return res.status(200).json({ 
                originalUrl: url,
                resolvedUrl: responseGet.url 
            });
        } catch (err) {
            return res.status(200).json({ 
                originalUrl: url,
                resolvedUrl: targetUrl 
            });
        }
    }
}
