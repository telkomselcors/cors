const blacklistUrls = [];
const whitelistOrigins = [ ".*" ];
function isListedInWhitelist(uri, listing) {
    let isListed = false;
    if (typeof uri === "string") {listing.forEach((pattern) => {if (uri.match(pattern) !== null) {isListed = true;}});} else {isListed = true;}
    return isListed;
}

addEventListener("fetch", async event => {
    event.respondWith((async function() {
        const isPreflightRequest = (event.request.method === "OPTIONS");
        const originUrl = new URL(event.request.url);
        const url = new URL(originUrl);
        const pathname = url.pathname;
        function setupCORSHeaders(headers) {
            headers.set("Access-Control-Allow-Origin", event.request.headers.get("Origin"));
            if (isPreflightRequest) {
                headers.set("Access-Control-Allow-Methods", event.request.headers.get("access-control-request-method"));
                const requestedHeaders = event.request.headers.get("access-control-request-headers");
                if (requestedHeaders) {headers.set("Access-Control-Allow-Headers", requestedHeaders);}
                headers.delete("X-Content-Type-Options");
            }
            return headers;
        }
        const ENDPOINT = '/u/'
        const S3TABLES_ENDPOINT = '/s3tables_proxy/'
        const S3TABLES_ENDPOINT_TEST = '/s3tables_proxy_test/'
        const origin_to_string = originUrl.toString();
        
        let targetUrl = "";
        let needsS3Tables = false;
        let skipCF = false;
        let needsCors = false;
        
        if (pathname.startsWith(ENDPOINT) && pathname != ENDPOINT) {
            targetUrl =    'https://' + origin_to_string.substr(origin_to_string.indexOf(ENDPOINT) + ENDPOINT.length);
            needsCors = true;
        } else if (pathname.startsWith(S3TABLES_ENDPOINT) && pathname != S3TABLES_ENDPOINT) {
            targetUrl =    'https://' + origin_to_string.substr(origin_to_string.indexOf(S3TABLES_ENDPOINT) + S3TABLES_ENDPOINT.length);
            needsCors = true;
            needsS3Tables = true;
        } else if (pathname.startsWith(S3TABLES_ENDPOINT_TEST) && pathname != S3TABLES_ENDPOINT_TEST) {
            targetUrl =    'https://' + origin_to_string.substr(origin_to_string.indexOf(S3TABLES_ENDPOINT_TEST) + S3TABLES_ENDPOINT_TEST.length);
            needsCors = true;
            needsS3Tables = true;
            skipCF = true;
        }
        
        const originHeader = event.request.headers.get("Origin");
        const connectingIp = event.request.headers.get("CF-Connecting-IP");
        if ((targetUrl !== "") && (!isListedInWhitelist(targetUrl, blacklistUrls)) && (isListedInWhitelist(originHeader, whitelistOrigins))) {
            let customHeaders = event.request.headers.get("x-cors-headers");
            if (customHeaders !== null) {
                try {
                    customHeaders = JSON.parse(customHeaders);
                } catch (e) {}
            }

            if (true) {
                const filteredHeaders = {};
                for (const [key, value] of event.request.headers.entries()) {
                    if (
                        (key.match("^origin") === null) &&
                        (key.match("eferer") === null) &&
                        ((!skipCF) || (key.match("^cf-") === null)) &&
                        (key.match("^x-forw") === null) &&
                        (key.match("^x-cors-headers") === null) &&
                        ((!needsS3Tables) || (key.toLowerCase().match("^if-range") === null)) &&
                        ((!needsS3Tables) || (key.toLowerCase().match("^sec-fetch-") === null)) &&
                        ((!needsS3Tables) || (key.toLowerCase().match("^x-host-override") === null))
                    ) {
                        filteredHeaders[key] = value;
                    }
                }
				if (customHeaders !== null) {Object.entries(customHeaders).forEach((entry) => (filteredHeaders[entry[0]] = entry[1]));}
                const newRequest = new Request(event.request, {
                    redirect: "follow",
                    headers: filteredHeaders
                });
                const response = await fetch(targetUrl, newRequest);
                var responseHeaders = new Headers(response.headers);
                var exposedHeaders = [];
                const allResponseHeaders = {};
                for (const [key, value] of response.headers.entries()) {
                    exposedHeaders.push(key);
                    allResponseHeaders[key] = value;
                }
	
		if (needsCors) {
			exposedHeaders.push("cors-received-headers");
			responseHeaders = setupCORSHeaders(responseHeaders);

			responseHeaders.set("Access-Control-Expose-Headers", exposedHeaders.join(","));
			responseHeaders.set("cors-received-headers", JSON.stringify(allResponseHeaders));
		}

                const responseBody = isPreflightRequest ? null : await response.arrayBuffer();

                const responseInit = {
                    headers: responseHeaders,
                    status: isPreflightRequest ? 200 : response.status,
                    statusText: isPreflightRequest ? "OK" : response.statusText
                };
                return new Response(responseBody, responseInit);

            } else {
                var responseHeaders = new Headers();
                responseHeaders = setupCORSHeaders(responseHeaders);
                let country = false;
                let colo = false;
                if (typeof event.request.cf !== "undefined") {
                    country = event.request.cf.country || false;
                    colo = event.request.cf.colo || false;
                }
                
                return new Response(
                    "Usage:\n" +
                    originUrl.origin + "/?uri\n\n" +
                    (originHeader !== null ? "Origin: " + originHeader + "\n" : "") +
                    "IP: " + connectingIp + "\n" +
                    (country ? "Country: " + country + "\n" : "") +
                    (colo ? "Datacenter: " + colo + "\n" : "") +
                    "\n" +
                    (customHeaders !== null ? "\nx-cors-headers: " + JSON.stringify(customHeaders) : ""),
                    {
                        status: 200,
                        headers: responseHeaders
                    }
                );
            }
        } else {
            return new Response("cyber4rt@protonmail.com",{status: 403,statusText: 'Forbidden',headers: {"Content-Type": "text/html"}});
        }
    })());
});
