var SignedXml = require('xml-crypto').SignedXml;
var fs = require('fs')
var algorithms = require('./algorithms');

var authnRequestXPath = '/*[local-name(.)="AuthnRequest" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]';
var defaultTransforms = [ 'http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#' ];

function signSamlPost(samlMessage, xpath, options) {
  if (!samlMessage) throw new Error('samlMessage is required');
  if (!xpath) throw new Error('xpath is required');
  if (!options || !options.privateCert) throw new Error('options.privateCert is required');

  var transforms = options.xmlSignatureTransforms || defaultTransforms;
  var sig = new SignedXml();
  if (options.signatureAlgorithm) {
    sig.signatureAlgorithm = algorithms.getSigningAlgorithm(options.signatureAlgorithm);
  }
  sig.addReference(xpath, transforms, algorithms.getDigestAlgorithm(options.digestAlgorithm));
  sig.signingKey = options.privateCert;
  sig.computeSignature(samlMessage);
  return sig.getSignedXml();
}

function signAuthnRequestPost(authnRequest, options) {
  return signSamlPost(authnRequest, authnRequestXPath, options);
}

function MyKeyInfo() {
  this.getKeyInfo = function(key, prefix) {
    prefix = prefix || '';
    prefix = prefix ? prefix + ':' : prefix;
    return "<" + prefix + "X509Data></" + prefix + "X509Data>";
  }
  this.getKey = function(keyInfo) {
    //you can use the keyInfo parameter to extract the key in any way you want       
    console.log("keyInfo: ", keyInfo);
    return fs.readFileSync("key.pem");
  }
}

function signXml(xml, xpath, key, dest) {
  var sig = new SignedXml();

  /*configure the signature object to use the custom algorithms*/
  // sig.signatureAlgorithm = "http://mySignatureAlgorithm"
  sig.keyInfoProvider = new MyKeyInfo();
  // sig.canonicalizationAlgorithm = "http://MyCanonicalization"
  // sig.addReference("//*[local-name(.)='x']", ["http://MyTransformation"], "http://myDigestAlgorithm")

  sig.signingKey = fs.readFileSync(key);
  sig.addReference(xpath);
  sig.computeSignature(xml);
  fs.writeFileSync(dest, sig.getSignedXml());
}


exports.signSamlPost = signSamlPost;
exports.signAuthnRequestPost = signAuthnRequestPost;