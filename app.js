const axios = require('axios');
const moment = require('moment');
var sha256 = require("crypto-js/sha256");
var HmacSHA256 = require("crypto-js/hmac-sha256");
var fs = require('fs');
const createHash = require("sha256-uint8array").createHash;

async function main() {
    var objectContent = fs.readFileSync("./1.png");
    var bucketName = '';
    var regionName = '';
    var awsAccessKey = '';
    var awsSecretKey = '';

    await putS3Object(bucketName, regionName, awsAccessKey, awsSecretKey, '/test/objectContent.png', objectContent, {'Content-Type': 'image/jpeg'});
    var objectContent =
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc tortor metus, sagittis eget augue ut,\n"
        + "feugiat vehicula risus. Integer tortor mauris, vehicula nec mollis et, consectetur eget tortor. In ut\n"
        + "elit sagittis, ultrices est ut, iaculis turpis. In hac habitasse platea dictumst. Donec laoreet tellus\n"
        + "at auctor tempus. Praesent nec diam sed urna sollicitudin vehicula eget id est. Vivamus sed laoreet\n"
        + "lectus. Aliquam convallis condimentum risus, vitae porta justo venenatis vitae. Phasellus vitae nunc\n"
        + "varius, volutpat quam nec, mollis urna. Donec tempus, nisi vitae gravida facilisis, sapien sem malesuada\n"
        + "purus, id semper libero ipsum condimentum nulla. Suspendisse vel mi leo. Morbi pellentesque placerat congue.\n"
        + "Nunc sollicitudin nunc diam, nec hendrerit dui commodo sed. Duis dapibus commodo elit, id commodo erat\n"
        + "congue id. Aliquam erat volutpat.\n";
    await putS3Object(bucketName, regionName, awsAccessKey, awsSecretKey, '/test/objectContent.txt', objectContent, {'Content-Type': 'text/plain'});
}

const SCHEME = "AWS4";
const ALGORITHM = "HMAC-SHA256";
const TERMINATOR = "aws4_request";

async function putS3Object(bucketName, regionName, awsAccessKey, awsSecretKey, path, objectContent, headers = {}) {
    if (!path.startsWith('/')) {
        path = '/' + path;
    }
    var endpointUrl = new URL("https://s3-" + regionName + ".amazonaws.com/" + bucketName + path);

    const contentHashString = createHash().update(objectContent).digest("hex");
    console.log('contentHashString: ' + contentHashString);
    //var contentHashString = sha256(objectContent).toString();

    headers = Object.assign(headers, {
        'x-amz-content-sha256': contentHashString,
        'content-length': objectContent.length,
        'x-amz-storage-class': 'REDUCED_REDUNDANCY',
        'x-amz-acl': 'public-read',
    });
    var httpMethod = 'PUT';
    var authorization = await computeSignature(endpointUrl, httpMethod, "s3", regionName, headers, null, contentHashString, awsAccessKey, awsSecretKey);
    console.log('authorization: ' + authorization);
    headers["Authorization"] = authorization;

    var options = {
        method: httpMethod,
        headers,
        data: objectContent,
        url: endpointUrl.toString()
    };

    var res = await axios(options);
    console.log('--------- Response content ---------');
    //console.log(res);
    console.log('------------------------------------');
    var resourceUrl = "https://" + bucketName + ".s3-" + regionName + ".amazonaws.com" + path;
    console.log('resourceUrl: ' + resourceUrl);
    return res && res.status ? resourceUrl : '';
}

async function computeSignature(endpointUrl, httpMethod, serviceName, regionName, headers, queryParameters, contentHashString, awsAccessKey, awsSecretKey) {
    var now = new Date();
    //var now = new Date(1616396954836);
    const dateTimeStamp = moment(now).utc().format().replaceAll('-', '').replaceAll(':', '');
    var hostHeader = endpointUrl.host;
    var port = endpointUrl.port;
    if (port && port.length > 0) {
        hostHeader = hostHeader.concat(':' + port)
    }
    headers['Host'] = hostHeader;
    headers['x-amz-date'] = dateTimeStamp;

    var canonicalizedHeaderNames = getCanonicalizeHeaderNames(headers);
    console.log(canonicalizedHeaderNames);
    var canonicalizedHeaders = getCanonicalizedHeaderString(headers);
    console.log(canonicalizedHeaders);
    var canonicalizedQueryParameters = getCanonicalizedQueryString(queryParameters);

    var canonicalRequest = getCanonicalRequest(endpointUrl, httpMethod,
        canonicalizedQueryParameters, canonicalizedHeaderNames,
        canonicalizedHeaders, contentHashString);
    console.log('--------- Canonical request --------');
    console.log(canonicalRequest);
    console.log('------------------------------------');

    var dateStamp = dateTimeStamp.substring(0, 8);
    var scope =  dateStamp + "/" + regionName + "/" + serviceName + "/" + TERMINATOR;
    var stringToSign = getStringToSign(SCHEME, ALGORITHM, dateTimeStamp, scope, canonicalRequest);
    console.log("--------- String to sign -----------");
    console.log(stringToSign);
    console.log("------------------------------------");

    //var enc = new TextEncoder(); // always utf-8
    var kSecret = SCHEME + awsSecretKey;
    console.log(kSecret);
    var kDate = HmacSHA256(dateStamp, kSecret);
    console.log('kDate: ' + kDate.toString());
    var kRegion = HmacSHA256(regionName, kDate);
    console.log('kRegion: ' + kRegion.toString());
    var kService = HmacSHA256(serviceName, kRegion);
    console.log('kService: ' + kService.toString());
    var kSigning = HmacSHA256(TERMINATOR, kService);
    console.log('kSigning: ' + kSigning.toString());
    var signature = HmacSHA256(stringToSign, kSigning);
    console.log('signature: ' + signature.toString());

    var credentialsAuthorizationHeader =
    "Credential=" + awsAccessKey + "/" + scope;
    var signedHeadersAuthorizationHeader =
        "SignedHeaders=" + canonicalizedHeaderNames;
    var signatureAuthorizationHeader =
        "Signature=" + signature.toString();

    var authorizationHeader = SCHEME + "-" + ALGORITHM + " "
        + credentialsAuthorizationHeader + ", "
        + signedHeadersAuthorizationHeader + ", "
        + signatureAuthorizationHeader;
    return authorizationHeader;
}

function getStringToSign(scheme, algorithm, dateTime, scope, canonicalRequest) {
    var stringToSign =
                scheme + "-" + algorithm + "\n" +
                dateTime + "\n" +
                scope + "\n" +
                sha256(canonicalRequest).toString();
    return stringToSign;
}

function getCanonicalRequest(endpoint, httpMethod, queryParameters, canonicalizedHeaderNames, canonicalizedHeaders, bodyHash) {
    var canonicalRequest =
                        httpMethod + "\n" +
                        getCanonicalizedResourcePath(endpoint) + "\n" +
                        queryParameters + "\n" +
                        canonicalizedHeaders + "\n" +
                        canonicalizedHeaderNames + "\n" +
                        bodyHash;
    return canonicalRequest;
}

function getCanonicalizedResourcePath(endpoint) {
    if ( endpoint == null ) {
        return "/";
    }
    var path = endpoint.pathname;
    if ( path == null || path.length == 0 ) {
        return "/";
    }
    
    var encodedPath = urlEncode(path, true);
    if (encodedPath.startsWith("/")) {
        return encodedPath;
    } else {
        return "/".concat(encodedPath);
    }
}

function urlEncode(url, keepPathSlash) {
    var encoded = encodeURIComponent(url);
    if (keepPathSlash) {
        encoded = encoded.replaceAll("%2F", "/");
    }
    return encoded;
}

function getCanonicalizeHeaderNames(headers) {
    var sortedHeaders = Object.keys(headers).sort((x, y) => {
        x = x.toUpperCase();
        y = y.toUpperCase();
        if (x < y) return -1;
        if (x > y) return 1;
        return 0;
    });
    var result = '';
    for (let item of sortedHeaders) {
        result += (item.toLowerCase() + ';');
    }
    if (result.endsWith(';')) result = result.substring(0, result.length - 1);
    return result;
}

function getCanonicalizedHeaderString(headers) {
    var sortedHeaders = Object.keys(headers).sort((x, y) => {
        x = x.toUpperCase();
        y = y.toUpperCase();
        if (x < y) return -1;
        if (x > y) return 1;
        return 0;
    });
    var result = '';
    for (let item of sortedHeaders) {
        result += (item.toLowerCase() + ':' + headers[item] + '\n');
    }
    //if (result.endsWith('\n')) result = result.substring(0, result.length - 1);
    return result;
}

function getCanonicalizedQueryString(parameters) {
    if (parameters == null) return '';
    //TODO
    return '';
}

main();