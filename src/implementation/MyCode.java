/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

import code.GuiException;
import com.sun.deploy.uitoolkit.impl.fx.ui.CertificateDialog.CertificateInfo;
import gui.Constants;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Certificate;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import sun.security.pkcs.PKCS7;
import x509.v3.CodeV3;

/**
 *
 * @author Mladen
 */
public class MyCode extends CodeV3 {
    
    private KeyStore keyStore;
    private static final String password = "lozinka";
    private static final String path = "podaci";
    private JcaPKCS10CertificationRequest csr;
    
    
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        try {
            keyStore = KeyStore.getInstance("BKS", "BC");
            keyStore.load(null, password.toCharArray());
            
            File keyFile = new File(path);
            
            if (keyFile.isFile() && keyFile.canRead()) {
                InputStream in = new FileInputStream(path);
                keyStore.load(in, password.toCharArray());
                in.close();
            }
            else {
                OutputStream out = new FileOutputStream(keyFile);
                keyStore.store(out, password.toCharArray());
                out.close();
            }
            
            return keyStore.aliases();
            
        } catch (KeyStoreException | NoSuchProviderException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public void resetLocalKeystore() {
        keyStore = null;
        File file = new File(path);
        if (file.isFile() && file.canRead())
            file.delete();
    }

    @Override
    public int loadKeypair(String string) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(string);
            
            access.setNotAfter(cert.getNotAfter());
            access.setNotBefore(cert.getNotBefore());
            
            access.setVersion(cert.getVersion()-1);
            
            Set<String> critical_extensions = cert.getCriticalExtensionOIDs();
            
            System.out.println(keyStore.getCertificateChain(string).length);
            
            // KRITICNE EKSTENZIJE
            if (critical_extensions != null)
            {
                // Basic Constraints
                access.setCritical(Constants.BC, critical_extensions.contains(Extension.basicConstraints.toString()));
                
                // AKI
                access.setCritical(Constants.AKID, critical_extensions.contains(Extension.authorityKeyIdentifier.toString()));
                
                //SKI
                access.setCritical(Constants.SKID, critical_extensions.contains(Extension.subjectKeyIdentifier.toString()));
                
                // Subject Alternate Name
                access.setCritical(Constants.SAN, critical_extensions.contains(Extension.subjectAlternativeName.toString()));
            }
                
            
            // Da li je CA
            if (cert.getBasicConstraints() != -1){
                access.setPathLen(Integer.toString(cert.getBasicConstraints()));
                access.setCA(true);
            }
            
            // Setovanje aloritma kljuca
            PublicKey key = (PublicKey) cert.getPublicKey();
            if (key.getAlgorithm().equals("DSA")){
                DSAPublicKey dsa = (DSAPublicKey) key;
            }
            else if (key.getAlgorithm().equals("RSA")) {
                RSAPublicKey rsa = (RSAPublicKey) key;
            }
            
            //access.setPublicKeyParameter(String.valueOf(dsa.getParams().getP().bitLength()));
            
            
            // Subject Alternative Names
            Collection<List<?>> subjectAltNames = cert.getSubjectAlternativeNames();
            if (subjectAltNames != null) {
                List<String> identities = new ArrayList<String>();
                for (final List<?> sanItem : subjectAltNames) {
                    ASN1InputStream decoder=null;
                        if(sanItem.toArray()[1] instanceof byte[])
                            decoder = new ASN1InputStream((byte[]) sanItem.toArray()[1]);
                        else if(sanItem.toArray()[1] instanceof String)
                            identities.add( (String) sanItem.toArray()[1] );
                        
                }
                String altField = "";
                int i=0;
                for(String s: identities){
                    if (i>0)
                        altField += ",";
                    altField += s;
                    i++;
                }
                
                access.setAlternativeName(Constants.SAN, altField);
            }
            
            
            
            // Setovanje polja Subject-a
            access.setSubject(cert.getSubjectDN().toString());
            
            
            // Setovanje polja Issuer-a
            access.setIssuer(cert.getIssuerDN().toString());
            access.setIssuerSignatureAlgorithm(cert.getSigAlgName());
            
            
           
            
            // Authority Key
            byte[] aki_bytes = cert.getExtensionValue(Extension.authorityKeyIdentifier.toString());
                if (aki_bytes != null) {
                AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(X509ExtensionUtil.fromExtensionValue(aki_bytes));
                if (aki != null){
                    access.setAuthorityIssuer(aki.getAuthorityCertIssuer().toString());
                    String keyIdentifierHex = new String(Hex.encode(aki.getKeyIdentifier()));
                    access.setAuthorityKeyID(keyIdentifierHex);
                    access.setAuthoritySerialNumber(aki.getAuthorityCertSerialNumber().toString());
                    access.setEnabledAuthorityKeyID(true);
                }
            }
            
            
            
            // Subject Key
            byte[] skiValueByte = cert.getExtensionValue(Extension.subjectKeyIdentifier.toString());
            if (skiValueByte != null) {
                byte[] octets = DEROctetString.getInstance(skiValueByte).getOctets();
                SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(octets);
                byte[] keyIdentifier = subjectKeyIdentifier.getKeyIdentifier();
                String keyIdentifierHex = new String(Hex.encode(keyIdentifier));
                access.setEnabledSubjectKeyID(true);
                access.setSubjectKeyID(keyIdentifierHex);
            }
            
            
            


    
            access.setPublicKeyAlgorithm(getCertPublicKeyAlgorithm(string));
            access.setPublicKeyParameter(getCertPublicKeyParameter(string));
            access.setSerialNumber(cert.getSerialNumber().toString());

            
            if (keyStore.isCertificateEntry(string))
                return 2;
            
            
            /*java.security.cert.Certificate[] cert_array = keyStore.getCertificateChain(string);
            for(java.security.cert.Certificate cert_ca: cert_array){
                PublicKey pb_ca = cert_ca.getPublicKey();
                try {
                    cert.verify(pb_ca);
                } catch (CertificateException ex) {
                    Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeyException ex) {
                    Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchProviderException ex) {
                    Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
                } catch (SignatureException ex) {
                    Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
                }
                System.out.println(cert_ca == cert);
            }*/
            
            return 1;
            
            
            
            
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateParsingException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return 0;
    }

    @Override
    public boolean saveKeypair(String string) {
        try {
            if (access.getVersion() != Constants.V3 || ! access.getPublicKeyAlgorithm().equals("DSA"))
                return false;
            
            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(access.getPublicKeyDigestAlgorithm());
            
            Date notBefore = access.getNotBefore();
            Date notAfter = access.getNotAfter();
            
            BigInteger serialNumber =new BigInteger(access.getSerialNumber());
            
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(access.getPublicKeyAlgorithm(), "BC");
            keyPairGenerator.initialize(Integer.parseInt(access.getPublicKeyParameter()));
            
            KeyPair keyPair = keyPairGenerator.genKeyPair();
            
            DSAPublicKey publicKey = (DSAPublicKey) keyPair.getPublic();
            DSAPrivateKey privateKey = (DSAPrivateKey) keyPair.getPrivate();
            
            SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair.getPublic().getEncoded())); 
            
            String subjectName = "";
            if (! access.getSubjectCommonName().equals(""))
                subjectName += "CN="+access.getSubjectCommonName();
            if (! access.getSubjectCountry().equals(""))
                subjectName += ((subjectName.length()>0) ? "," : "") + "C="+access.getSubjectCountry();
            if (! access.getSubjectState().equals(""))
                subjectName += ((subjectName.length()>0) ? "," : "") + "ST="+access.getSubjectState();
            if (! access.getSubjectLocality().equals(""))
                subjectName += ((subjectName.length()>0) ? "," : "") + "L="+access.getSubjectLocality();
            if (! access.getSubjectOrganization().equals(""))
                subjectName += ((subjectName.length()>0) ? "," : "") + "O="+access.getSubjectOrganization();
            if (! access.getSubjectOrganizationUnit().equals(""))
                subjectName += ((subjectName.length()>0) ? "," : "") + "OU="+access.getSubjectOrganizationUnit();
           
            X500Principal name = new X500Principal(subjectName);
           
            X509v3CertificateBuilder x509Builder = new JcaX509v3CertificateBuilder(name, serialNumber, notBefore, notAfter, name, publicKey);
            
            
            // Subject Alternate Names
            if (access.isCritical(Constants.SAN)) {
                String[] altNames = access.getAlternativeName(Constants.SAN);
                List<GeneralName> altNamesArray = new ArrayList<GeneralName>();
                for(String altName: altNames)
                    altNamesArray.add(new GeneralName(GeneralName.dNSName, altName));
                GeneralNames subjectAltNames = GeneralNames.getInstance(new DERSequence((GeneralName[]) altNamesArray.toArray(new GeneralName[] {})));
                x509Builder.addExtension(Extension.subjectAlternativeName, access.isCritical(Constants.SAN), subjectAltNames);
            }
            
            
            // Basic Constraints
            if (access.isCritical(Constants.BC)) {
                if (access.isCA())
                    x509Builder.addExtension(Extension.basicConstraints, access.isCritical(Constants.BC), new BasicConstraints(Integer.parseInt(access.getPathLen())));
                else
                    x509Builder.addExtension(Extension.basicConstraints, access.isCritical(Constants.BC), new BasicConstraints(false));
            }
            
            
            // Subject Key Identfier
            if (access.getEnabledSubjectKeyID()) {
                x509Builder.addExtension(Extension.subjectKeyIdentifier, access.isCritical(Constants.SKID), new SubjectKeyIdentifier(publicKey.getEncoded()));
            }
            
           
            // Authority Key Identifier
            if (access.getEnabledAuthorityKeyID()) {
                SubjectPublicKeyInfo su = new SubjectPublicKeyInfo(sigAlgId, publicKey.getEncoded());
                GeneralName gn = new GeneralName(new X509Name(name.toString()));
                GeneralNames gnn = new GeneralNames(gn);
                System.out.println(name.toString());

                x509Builder.addExtension(Extension.authorityKeyIdentifier, access.isCritical(Constants.AKID), new AuthorityKeyIdentifier(publicKeyInfo.getEncoded(), gnn, serialNumber));
            }
            
            
            
           
            ContentSigner contentSigner = new JcaContentSignerBuilder(access.getPublicKeyDigestAlgorithm()).setProvider("BC").build(privateKey);
            
            X509Certificate xc = new JcaX509CertificateConverter().setProvider("BC").getCertificate(x509Builder.build(contentSigner));
            
            keyStore.setKeyEntry(string, privateKey, null, new X509Certificate[] { xc });
            
            updateKeyStore();
            
            return true;
            //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (OperatorCreationException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    @Override
    public boolean removeKeypair(String string) {
        try {
            keyStore.deleteEntry(string);
            updateKeyStore();
            return true;
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    @Override
    public boolean importKeypair(String string, String string1, String string2) {
        FileInputStream input = null;
        try {
            keyStore = KeyStore.getInstance("BKS", "BC");
            keyStore.load(null, password.toCharArray());
            
            File keyFile = new File(path);
            
            if (keyFile.isFile() && keyFile.canRead()) {
                InputStream in = new FileInputStream(path);
                keyStore.load(in, password.toCharArray());
                in.close();
            }
            else {
                OutputStream out = new FileOutputStream(keyFile);
                keyStore.store(out, password.toCharArray());
                out.close();
            }
            
            KeyStore keyStoreToImport = KeyStore.getInstance("PKCS12", "BC");
            File importFile = new File(string1);
            if (! importFile.canRead() || ! importFile.exists())
                return false;
            input = new FileInputStream(importFile);
            keyStoreToImport.load(input, string2.toCharArray());
            
            X509Certificate[] certArray = null;
            Enumeration<String> enumArray = keyStoreToImport.aliases();
            String alias = enumArray.nextElement();
            
            /*while(enumArray.hasMoreElements()){
                String enumItem = enumArray.nextElement();
                DSAPrivateKey pKey = (DSAPrivateKey) keyStoreToImport.getKey(string, string2.toCharArray());
                X509Certificate cert = (X509Certificate) keyStoreToImport.getCertificate(enumItem);
                certArray = (X509Certificate[]) keyStoreToImport.getCertificateChain(enumItem);
            }*/
            
            PrivateKey pKey = (PrivateKey) keyStoreToImport.getKey(alias, string2.toCharArray());
            X509Certificate cert = (X509Certificate) keyStoreToImport.getCertificate(alias);

            keyStore.setKeyEntry(string, pKey, null, new X509Certificate[] { cert });
            updateKeyStore();
            return true;
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                input.close();
            } catch (IOException ex) {
                Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return false;
    }

    @Override
    public boolean exportKeypair(String string, String string1, String string2) {
        try {
            KeyStore keyStoreToExport = KeyStore.getInstance("PKCS12", "BC");
            keyStoreToExport.load(null, string2.toCharArray());
            java.security.cert.Certificate[] cert_list = keyStore.getCertificateChain(string);
            DSAPrivateKey pKey = (DSAPrivateKey) keyStore.getKey(string, null);
 
            keyStoreToExport.setKeyEntry(string, pKey, password.toCharArray(), cert_list);
            
            FileOutputStream file = new FileOutputStream(string1);
            keyStoreToExport.store(file, string2.toCharArray());
            file.close();
            return true;
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    @Override
    public boolean importCertificate(String file, String keypair_name) {
        try {
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
                    .generateCertificate(new FileInputStream(file));
            keyStore.setCertificateEntry(keypair_name, cert);
            updateKeyStore();
            return true;
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    @Override
    public boolean exportCertificate(String file, String keypair_name, int encoding, int format) {
        try {
            
            // HEAD ONLY
            if (format == 0) {
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(keypair_name);
                if (encoding == Constants.PEM) {
                    JcaPEMWriter pemWrt = new JcaPEMWriter(new FileWriter(file));
                    pemWrt.writeObject(cert);
                    pemWrt.flush();
                    pemWrt.close();
                }

                else {
                    FileOutputStream fileWrite = new FileOutputStream(new File(file));
                    fileWrite.write(cert.getEncoded());
                    fileWrite.flush();
                    fileWrite.close();
                }
            }
            
            // ENTIRE CHAIN
            else {
                java.security.cert.Certificate[] cert_list = keyStore.getCertificateChain(keypair_name);
                JcaPEMWriter pemWrt = new JcaPEMWriter(new FileWriter(file));
                for(java.security.cert.Certificate c: cert_list)
                    pemWrt.writeObject(c);
                pemWrt.flush();
                pemWrt.close();
            }
            

            return true;
            
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    @Override
    public boolean exportCSR(String string, String string1, String string2) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(string1);
            PrivateKey pKey = (PrivateKey) keyStore.getKey(string1, null);
            JcaPKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                    cert.getSubjectX500Principal(), cert.getPublicKey());
            JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(string2);
            ContentSigner signer = csBuilder.build(pKey);
            PKCS10CertificationRequest csr_output = p10Builder.build(signer);
            FileOutputStream out = new FileOutputStream(string);
            out.write(csr_output.getEncoded());
            out.close();
            return true;
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (OperatorCreationException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    @Override
    public String importCSR(String string) {
        FileInputStream in = null;
        try { 
            in = new FileInputStream(string);
            csr = new JcaPKCS10CertificationRequest(Files.readAllBytes(Paths.get(string)));

            return csr.getSubject().toString();
                    } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                in.close();
            } catch (IOException ex) {
                Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return null;
    }

    @Override
    public boolean signCSR(String file, String keypair_name, String algorithm) {
        try {
            X509Certificate ca = (X509Certificate) keyStore.getCertificate(keypair_name);
            X500Name issuer = new X500Name(ca.getSubjectX500Principal().getName());
            PrivateKey caKey = (PrivateKey) keyStore.getKey(keypair_name, null);
            
           
            JcaX509CertificateHolder caHolder = new JcaX509CertificateHolder(ca);
            
            Date from = access.getNotBefore();
            Date to = access.getNotAfter();
            BigInteger serial = new BigInteger(access.getSerialNumber());
            
            //X509v3CertificateBuilder certgen = new X509v3CertificateBuilder(issuer, serial, from, to, csr.getSubject(), csr.getSubjectPublicKeyInfo());
            JcaX509v3CertificateBuilder certgen = new JcaX509v3CertificateBuilder(caHolder.getIssuer(), serial, from, to, csr.getSubject(), csr.getPublicKey());
           /*certgen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
            
            certgen.addExtension(Extension.subjectKeyIdentifier, false, csr.getSubjectPublicKeyInfo());
            certgen.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(new GeneralNames(new GeneralName(new X509Name(ca.getSubjectX500Principal().getName()))), ca.getSerialNumber()));*/
            
            
           
            // Subject Alternate Names
            if (access.isCritical(Constants.SAN)) {
                String[] altNames = access.getAlternativeName(Constants.SAN);
                List<GeneralName> altNamesArray = new ArrayList<GeneralName>();
                for(String altName: altNames)
                    altNamesArray.add(new GeneralName(GeneralName.dNSName, altName));
                GeneralNames subjectAltNames = GeneralNames.getInstance(new DERSequence((GeneralName[]) altNamesArray.toArray(new GeneralName[] {})));
                certgen.addExtension(Extension.subjectAlternativeName, access.isCritical(Constants.SAN), subjectAltNames);
            }
            
                      
            // Basic Constraints
            if (access.isCA())
                certgen.addExtension(Extension.basicConstraints, access.isCritical(Constants.BC), new BasicConstraints(Integer.parseInt(access.getPathLen())));
            else
                certgen.addExtension(Extension.basicConstraints, access.isCritical(Constants.BC), new BasicConstraints(false));
            
                   
            // Subject Key Identfier
            if (access.getEnabledSubjectKeyID()) {
                certgen.addExtension(Extension.subjectKeyIdentifier, access.isCritical(Constants.SKID), new SubjectKeyIdentifier(csr.getPublicKey().getEncoded()));
            }
            
            
            
            // Authority Key Identifier
            if (access.getEnabledAuthorityKeyID()) {
                AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
                SubjectPublicKeyInfo su = new SubjectPublicKeyInfo(sigAlgId, ca.getPublicKey().getEncoded());
                GeneralName gn = new GeneralName(issuer);
                GeneralNames gnn = new GeneralNames(gn);
                //System.out.println(name.toString());

                //certgen.addExtension(Extension.authorityKeyIdentifier, access.isCritical(Constants.AKID), new AuthorityKeyIdentifier(su, gnn, ca.getSerialNumber()));
                certgen.addExtension(Extension.authorityKeyIdentifier, access.isCritical(Constants.AKID), new AuthorityKeyIdentifier(ca.getPublicKey().getEncoded(), gnn, serial));
            }
            
            
            
            /*if (access.isCritical(Constants.AKID)) {
                SubjectPublicKeyInfo CAsubjectInfo = SubjectPublicKeyInfo.getInstance(ca.getPublicKey().getEncoded());
                
                AuthorityKeyIdentifier a = new AuthorityKeyIdentifier(
                CAsubjectInfo,
                new GeneralNames(new GeneralName(new X509Name(ca.getSubjectX500Principal().toString()))),
                serial
                );
                
                certgen.addExtension(Extension.authorityKeyIdentifier, access.isCritical(Constants.AKID), a);
            }*/
            
            
            
            
            
            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
            
            
            
//            ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(PrivateKeyFactory.createKey(caKey.getEncoded()));
//            X509CertificateHolder holder = certgen.build(signer);
//            byte[] certencoded = holder.toASN1Structure().getEncoded();
//            
//            
//            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
//            
//            signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(caKey);
//            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer, ca));
//            generator.addCertificate(new X509CertificateHolder(certencoded));
//            generator.addCertificate(new X509CertificateHolder(ca.getEncoded()));
//            CMSTypedData content = new CMSProcessableByteArray(certencoded);
//            CMSSignedData signeddata = generator.generate(content, true);

            CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
            ContentSigner sha1Signer = new JcaContentSignerBuilder(algorithm).setProvider("BC").build(caKey);
            
            X509CertificateHolder holder = certgen.build(sha1Signer);
            
            cmsSignedDataGenerator
                    .addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
				new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
		.build(sha1Signer, ca));
            //cmsSignedDataGenerator.addCertificate(holder);
            
            
            byte[] certencoded = holder.toASN1Structure().getEncoded();
            
            cmsSignedDataGenerator.addCertificate(holder);
            
            java.security.cert.Certificate[] cert_array = keyStore.getCertificateChain(keypair_name);
            for(java.security.cert.Certificate cert_instance: cert_array){
                X509Certificate x509=(X509Certificate)cert_instance;
                X509CertificateHolder hold = new JcaX509CertificateHolder(x509);
                cmsSignedDataGenerator.addCertificate(hold);
                System.out.println("A");
            }
            
            /*cmsSignedDataGenerator.addCertificate(new JcaX509CertificateHolder(ca);
            cmsSignedDataGenerator.addCertificate(holder);*/
            
            CMSTypedData chainMessage = new CMSProcessableByteArray(certencoded);
            System.out.println(certencoded);
            CMSSignedData signeddata = cmsSignedDataGenerator.generate(chainMessage, false);
            
            FileOutputStream out = new FileOutputStream(file);
            JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(out));
            
            JcaX509CertificateConverter jcaConverter = new JcaX509CertificateConverter();
            X509Certificate out_cert = jcaConverter.getCertificate(holder);
            pemWriter.writeObject(out_cert);
            pemWriter.writeObject(caHolder);
            pemWriter.close();
            
           /* System.out.println("A");
            System.out.println(out_cert);
            System.out.println(caHolder);*/
            //ByteArrayOutputStream out = new ByteArrayOutputStream();
            //out.write("-----BEGIN PKCS #7 SIGNED DATA-----\n".getBytes("ISO-8859-1"));
            //out.write(Base64.encode(signeddata.getEncoded()));
            //out.write("\n-----END PKCS #7 SIGNED DATA-----\n".getBytes("ISO-8859-1"));
            //out.close();
            
            /*FileOutputStream outFile = new FileOutputStream(string);
            out.writeTo(outFile);
            outFile.close();*/
            return true;
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertIOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (OperatorCreationException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CMSException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    @Override
    public boolean importCAReply(String file, String keypair_name) {
        try {
            FileInputStream in;
            File file_instance = new File(file);
            in = new FileInputStream(file_instance);

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");
            /*Collection coll = certificateFactory.generateCertificates(in);
            System.out.println(coll);*/
            
            Collection<? extends java.security.cert.Certificate> coll = certificateFactory.generateCertificates(in);
            
            System.out.println("BROJ "+coll.size());
            
            java.security.cert.Certificate[] certificates = (java.security.cert.Certificate[]) coll.toArray(new java.security.cert.Certificate[coll.size()]);
            
           
            PrivateKey k = (PrivateKey) keyStore.getKey(keypair_name, null);
            keyStore.setKeyEntry(keypair_name, k, null, (java.security.cert.Certificate[]) certificates);
            
            updateKeyStore();
            return true;
            
            /*byte fileContent[] = new byte[(int)file.length()];
            in.read(fileContent);*/
            //String s = new String(fileContent);

           /* InputStream signatureIn = new ByteArrayInputStream(fileContent);
            ASN1Primitive obj = new ASN1InputStream(signatureIn).readObject();
            //ContentInfo contentInfo = ContentInfo.getInstance(obj);
            
            System.out.println(obj);*/
            
            
            /*PKCS7 pkcs7 = new PKCS7(fileContent);
            System.out.println(pkcs7);*/
            
            /*CMSSignedData s = new CMSSignedData(fileContent);
            System.out.println(s);*/
            
            
            


        } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    @Override
    public boolean canSign(String string) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(string);
            if (cert.getBasicConstraints() != -1)
                return true;
            
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    @Override
    public String getSubjectInfo(String string) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(string);
            return cert.getSubjectX500Principal().toString().replaceAll("\\s+","");
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public String getCertPublicKeyAlgorithm(String string) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(string);
            PublicKey pKey = cert.getPublicKey();
            return pKey.getAlgorithm();
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public String getCertPublicKeyParameter(String string) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(string);
            PublicKey key = (PublicKey) cert.getPublicKey();
            
            if (key.getAlgorithm().equals("DSA")){
                DSAPublicKey dsa = (DSAPublicKey) key;
                System.out.println(String.valueOf(dsa.getParams().getP().bitLength()));
                return String.valueOf(dsa.getParams().getP().bitLength());
            }
            else if (key.getAlgorithm().equals("RSA")) {
                RSAPublicKey rsa = (RSAPublicKey) key;
                System.out.println(rsa.getModulus().bitLength());
                return String.valueOf(rsa.getModulus().bitLength());
            }
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    
    
    private void updateKeyStore() {
        OutputStream out = null;
        try {
            out = new FileOutputStream(path);
            keyStore.store(out, password.toCharArray());
            out.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                out.close();
            } catch (IOException ex) {
                Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
}
