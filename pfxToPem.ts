const forge = require("node-forge");
const fs = require('fs');

async function main() {
    var p12Pem = fs.readFileSync("azurite.pfx");
    var a=convertPFX(p12Pem,"123456");
    console.log(a);
}

main();

export function convertPFX(pfx: Buffer | string, passphrase?: string) {
  let p12buffer: string;
 
  if (Buffer.isBuffer(pfx)) {
    p12buffer = pfx.toString("base64");
  } else {
    p12buffer = pfx;
  }

  const asn = forge.asn1.fromDer(forge.util.decode64(p12buffer));
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn, true, passphrase);

  const keyData = p12
    .getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })
    [forge.pki.oids.pkcs8ShroudedKeyBag].concat(
      p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag]
    );
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[
    forge.pki.oids.certBag
  ];

  console.log(keyData);
  // convert a Forge private key to an ASN.1 RSAPrivateKey
  const rsaPrivateKey = forge.pki.privateKeyToAsn1(keyData[0].key);

  // wrap an RSAPrivateKey ASN.1 object in a PKCS#8 ASN.1 PrivateKeyInfo
  const privateKeyInfo = forge.pki.wrapRsaPrivateKey(rsaPrivateKey);

  // convert a PKCS#8 ASN.1 PrivateKeyInfo to PEM
//   const pem = forge.pki.privateKeyInfoToPem(privateKeyInfo);

  return {
    certificate: forge.pki.certificateToPem(certBags[0].cert),
    key: keyData.length ? forge.pki.privateKeyInfoToPem(privateKeyInfo) : undefined,
  };
}
