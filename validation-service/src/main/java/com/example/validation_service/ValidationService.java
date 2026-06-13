package com.example.validation_service;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Service;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.*;
import java.time.LocalDateTime;
import java.util.*;

@Service
public class ValidationService {

    private final ValidationRepository repository;

    public ValidationService(ValidationRepository repository) {
        this.repository = repository;
    }


    public boolean validatePdf(InputStream pdfStream, String fileName) {
        boolean isValid = false;
        String baseSignerInfo = "Нема дигитален потпис";
        String statusReason = "";

        try {
            byte[] pdfBytes = pdfStream.readAllBytes();

            try (PDDocument document = Loader.loadPDF(pdfBytes)) {
                List<PDSignature> signatures = document.getSignatureDictionaries();

                if (signatures != null && !signatures.isEmpty()) {

                    PDSignature sig = null;
                    for (PDSignature s : signatures) {
                        byte[] contents = s.getContents(pdfBytes);
                        if (contents != null && contents.length > 0) {
                            try {
                                CMSSignedData testData = new CMSSignedData(contents);
                                for (X509CertificateHolder holder : testData.getCertificates().getMatches(null)) {
                                    X509Certificate testCert = new JcaX509CertificateConverter().getCertificate(holder);

                                    if (testCert.getBasicConstraints() == -1) {
                                        testCert.checkValidity();
                                        sig = s;
                                        break;
                                    }
                                }
                            } catch (Exception ignored) {}
                        }
                        if (sig != null) break;
                    }

                    if (sig == null) {
                        sig = signatures.get(signatures.size() - 1);
                    }

                    byte[] signatureContents = sig.getContents(pdfBytes);
                    baseSignerInfo = (sig.getName() != null) ? sig.getName() : "Непознат потписник";

                    if (signatureContents != null && signatureContents.length > 0) {
                        try {
                            CMSSignedData signedData = new CMSSignedData(signatureContents);
                            Store<X509CertificateHolder> certificatesStore = signedData.getCertificates();
                            Collection<X509CertificateHolder> matches = certificatesStore.getMatches(null);

                            List<X509Certificate> certChainList = new ArrayList<>();
                            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

                            for (X509CertificateHolder holder : matches) {
                                certChainList.add(converter.getCertificate(holder));
                            }

                            X509Certificate cert = null;
                            var signerInfos = signedData.getSignerInfos().getSigners();
                            if (!signerInfos.isEmpty()) {
                                var signerInfo = signerInfos.iterator().next();
                                var sid = signerInfo.getSID();

                                for (X509Certificate c : certChainList) {
                                    boolean serialMatch = c.getSerialNumber().equals(sid.getSerialNumber());
                                    boolean issuerMatch = sid.getIssuer() != null &&
                                            c.getIssuerX500Principal().getName().equalsIgnoreCase(sid.getIssuer().toString());

                                    if (serialMatch && issuerMatch) {
                                        cert = c;
                                        break;
                                    }
                                }

                                if (cert == null) {
                                    for (X509Certificate c : certChainList) {
                                        if (c.getSerialNumber().equals(sid.getSerialNumber())) {
                                            cert = c;
                                            break;
                                        }
                                    }
                                }
                            }

                            if (cert == null && !certChainList.isEmpty()) {
                                for (X509Certificate c : certChainList) {
                                    if (c.getBasicConstraints() == -1) {
                                        cert = c;
                                        break;
                                    }
                                }
                            }

                            if (cert == null && !certChainList.isEmpty()) {
                                cert = certChainList.get(0);
                            }

                            if (cert != null) {
                                String subject = parseCN(cert.getSubjectX500Principal().getName());
                                String issuer = parseCN(cert.getIssuerX500Principal().getName());

                                baseSignerInfo = "Потпишан од: " + subject + " | Издавач: " + issuer;

                                try {
                                    byte[] signedContentBytes = sig.getSignedContent(pdfBytes);
                                    CMSTypedData cmsSub = new CMSProcessableByteArray(signedContentBytes);
                                    CMSSignedData signedDataWithContent = new CMSSignedData(cmsSub, signatureContents);

                                    var signers = signedDataWithContent.getSignerInfos().getSigners();
                                    if (signers.isEmpty()) {
                                        throw new Exception("Не е пронајден потписник во CMS содржината");
                                    }

                                    SignerInformation signerInfo = signers.iterator().next();
                                    boolean signatureValid = signerInfo.verify(
                                            new JcaSimpleSignerInfoVerifierBuilder().build(cert)
                                    );

                                    if (!signatureValid) {
                                        throw new Exception("Математички невалиден криптографски потпис");
                                    }

                                    cert.checkValidity();
                                    verifyTrustPath(cert, certChainList);

                                    isValid = true;
                                    statusReason = "";

                                } catch (CertificateExpiredException e) {
                                    isValid = false;
                                    statusReason = " (ИСТЕЧЕН СЕРТИФИКАТ)";
                                } catch (CertificateNotYetValidException e) {
                                    isValid = false;
                                    statusReason = " (НЕВАЛИДЕН ДАТУМ)";
                                } catch (Exception e) {
                                    isValid = false;
                                    System.err.println("Грешка при крипто верификација за " + fileName + ": " + e.getMessage());
                                    statusReason = " (НЕВАЛИДЕН ПОТПИС ИЛИ СИНЏИР НА ДОВЕРБА)";
                                }
                            }
                        } catch (Exception certEx) {
                            isValid = false;
                            statusReason = " (Проблем при читање на крипто формат)";
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Грешка при парсирање на документот: " + e.getMessage());
            baseSignerInfo = "Грешка при вчитување на документот";
        }

        String finalSignerName = baseSignerInfo + statusReason;
        saveToDatabase(fileName, finalSignerName, isValid);
        return isValid;
    }


    public boolean validateStandaloneCertificate(InputStream certStream, String fileName) {
        boolean isValid = false;
        String baseSignerInfo = "Невалиден сертификат фајл";
        String statusReason = "";

        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate targetCert = (X509Certificate) factory.generateCertificate(certStream);

            if (targetCert != null) {
                String subject = parseCN(targetCert.getSubjectX500Principal().getName());
                String issuer = parseCN(targetCert.getIssuerX500Principal().getName());

                baseSignerInfo = "Сертификат за: " + subject + " | Издавач: " + issuer;

                try {
                    targetCert.checkValidity();

                    List<X509Certificate> singleCertList = Collections.singletonList(targetCert);
                    verifyTrustPath(targetCert, singleCertList);

                    isValid = true;
                    statusReason = " [ВЕРИФИКУВАН ФАЈЛ]";

                } catch (CertificateExpiredException e) {
                    isValid = false;
                    statusReason = " (ИСТЕЧЕН СЕРТИФИКАТ)";
                } catch (CertificateNotYetValidException e) {
                    isValid = false;
                    statusReason = " (НЕВАЛИДЕН ДАТУМ)";
                } catch (Exception e) {
                    isValid = false;
                    System.err.println("Грешка при верификација на сертификат фајл " + fileName + ": " + e.getMessage());
                    statusReason = " (НЕУСПЕШНА ВЕРИФИКАЦИЈА НА СИНЏИР НА ДОВЕРБА)";
                }
            }
        } catch (Exception e) {
            System.err.println("Грешка при парсирање на посебен сертификат: " + e.getMessage());
            baseSignerInfo = "Грешка при парсирање на сертификатот";
        }

        String finalSignerName = baseSignerInfo + statusReason;
        saveToDatabase(fileName, finalSignerName, isValid);
        return isValid;
    }

    public boolean validateP7sSignature(InputStream p7sStream, String fileName) {
        boolean isValid = false;
        String baseSignerInfo = "Невалиден .p7s дигитален потпис";
        String statusReason = "";

        try {
            byte[] p7sBytes = p7sStream.readAllBytes();
            CMSSignedData signedData = new CMSSignedData(p7sBytes);

            Store<X509CertificateHolder> certificatesStore = signedData.getCertificates();
            Collection<X509CertificateHolder> matches = certificatesStore.getMatches(null);

            List<X509Certificate> certChainList = new ArrayList<>();
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

            for (X509CertificateHolder holder : matches) {
                certChainList.add(converter.getCertificate(holder));
            }

            X509Certificate cert = null;
            var signerInfos = signedData.getSignerInfos().getSigners();
            if (!signerInfos.isEmpty()) {
                SignerInformation signerInfo = signerInfos.iterator().next();
                var sid = signerInfo.getSID();

                for (X509Certificate c : certChainList) {
                    if (c.getSerialNumber().equals(sid.getSerialNumber())) {
                        cert = c;
                        break;
                    }
                }

                if (cert != null) {
                    String subject = parseCN(cert.getSubjectX500Principal().getName());
                    String issuer = parseCN(cert.getIssuerX500Principal().getName());

                    baseSignerInfo = "Документ потпишан од: " + subject + " | Издавач: " + issuer;

                    try {
                        boolean signatureValid = signerInfo.verify(
                                new JcaSimpleSignerInfoVerifierBuilder().build(cert)
                        );

                        if (!signatureValid) {
                            throw new Exception("Математички невалиден криптографски потпис");
                        }

                        cert.checkValidity();
                        verifyTrustPath(cert, certChainList);
                        isValid = true;
                        statusReason = " [ВЕРИФИКУВАН ОПШТ ДОКУМЕНТ]";

                    } catch (CertificateExpiredException e) {
                        isValid = false;
                        statusReason = " (ИСТЕЧЕН СЕРТИФИКАТ ВО ПОТПИСОТ)";
                    } catch (CertificateNotYetValidException e) {
                        isValid = false;
                        statusReason = " (НЕВАЛИДЕН ДАТУМ)";
                    } catch (Exception e) {
                        isValid = false;
                        statusReason = " (НЕВАЛИДЕН CAdES СИНЏИР НА ДОВЕРБА)";
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Грешка при валидација на .p7s фајл: " + e.getMessage());
            baseSignerInfo = "Грешка при парсирање на .p7s дигитален потпис";
        }

        String finalSignerName = baseSignerInfo + statusReason;
        saveToDatabase(fileName, finalSignerName, isValid);
        return isValid;
    }


    public boolean validateOfficeDocument(InputStream officeStream, String fileName) {
        boolean isValid = false;
        String baseSignerInfo = "Нема пронајден дигитален потпис во Office документот";
        String statusReason = "";

        try {
            byte[] officeBytes = officeStream.readAllBytes();

            java.util.zip.ZipInputStream zip = new java.util.zip.ZipInputStream(new ByteArrayInputStream(officeBytes));
            java.util.zip.ZipEntry entry;
            byte[] signatureXmlBytes = null;

            while ((entry = zip.getNextEntry()) != null) {
                String entryName = entry.getName().toLowerCase();
                if (entryName.contains("_xmlparts/sig") || entryName.contains("signature")) {
                    signatureXmlBytes = zip.readAllBytes();
                    break;
                }
            }

            if (signatureXmlBytes != null) {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                Collection<? extends java.security.cert.Certificate> certs =
                        factory.generateCertificates(new ByteArrayInputStream(signatureXmlBytes));

                if (certs != null && !certs.isEmpty()) {
                    X509Certificate cert = null;
                    List<X509Certificate> certChainList = new ArrayList<>();

                    for (Object c : certs) {
                        if (c instanceof X509Certificate) {
                            X509Certificate current = (X509Certificate) c;
                            certChainList.add(current);
                            if (current.getBasicConstraints() == -1) {
                                cert = current;
                            }
                        }
                    }

                    if (cert == null && !certChainList.isEmpty()) {
                        cert = certChainList.get(0);
                    }

                    if (cert != null) {
                        String subject = parseCN(cert.getSubjectX500Principal().getName());
                        String issuer = parseCN(cert.getIssuerX500Principal().getName());

                        baseSignerInfo = "Office документ потпишан од: " + subject + " | Издавач: " + issuer;

                        try {
                            cert.checkValidity();
                            verifyTrustPath(cert, certChainList);
                            isValid = true;

                            byte[] qcStatementExtension = cert.getExtensionValue("1.3.6.1.5.5.7.1.3");
                            if (qcStatementExtension != null || issuer.contains("KIBS") || issuer.contains("Telekom")) {
                                statusReason = " [ВЕРИФИКУВАН ЕУ XAdES/OOXML ДОКУМЕНТ]";
                            } else {
                                statusReason = " [ВЕРИФИКУВАН ОФИС ДОКУМЕНТ]";
                            }

                        } catch (CertificateExpiredException e) {
                            isValid = false;
                            statusReason = " (ИСТЕЧЕН СЕРТИФИКАТ ВО ДОКУМЕНТОТ)";
                        } catch (CertificateNotYetValidException e) {
                            isValid = false;
                            statusReason = " (НЕВАЛИДЕН ДАТУМ)";
                        } catch (Exception e) {
                            isValid = false;
                            statusReason = " (НЕУСПЕШНА ВЕРИФИКАЦИЈА НА СИНЏИР ОД ДОКУМЕНТОТ)";
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Грешка при валидација на Office документ: " + e.getMessage());
            baseSignerInfo = "Грешка при парсирање на Office документот";
        }

        String finalSignerName = baseSignerInfo + statusReason;
        saveToDatabase(fileName, finalSignerName, isValid);
        return isValid;
    }

    private void verifyTrustPath(X509Certificate targetCert, List<X509Certificate> allCerts) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);

        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                for (X509Certificate ca : ((X509TrustManager) tm).getAcceptedIssuers()) {
                    trustStore.setCertificateEntry(ca.getSerialNumber().toString(), ca);
                }
            }
        }

        addTrustedCert(trustStore, "/trusted-roots/kibs-root.crt", "kibs-root");
        addTrustedCert(trustStore, "/trusted-roots/telekom-root.crt", "telekom-root");

        List<X509Certificate> certsForStore = new ArrayList<>(allCerts);

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(targetCert);

        PKIXBuilderParameters params = new PKIXBuilderParameters(trustStore, selector);

        CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(certsForStore));
        params.addCertStore(certStore);
        params.setRevocationEnabled(false);

        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
        PKIXRevocationChecker revChecker = (PKIXRevocationChecker) builder.getRevocationChecker();
        revChecker.setOptions(EnumSet.of(
                PKIXRevocationChecker.Option.PREFER_CRLS,
                PKIXRevocationChecker.Option.SOFT_FAIL
        ));
        params.addCertPathChecker(revChecker);

        builder.build(params);
    }

    private void addTrustedCert(KeyStore trustStore, String resourcePath, String alias) {
        try (InputStream in = getClass().getResourceAsStream(resourcePath)) {
            if (in != null) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
                trustStore.setCertificateEntry(alias, cert);
            }
        } catch (Exception e) {
            System.err.println("Неуспешно автоматско инјектирање на Root CA: " + resourcePath);
        }
    }

    private String parseCN(String subject) {
        if (subject == null) return "Непознат";
        try {
            for (String part : subject.split(",")) {
                String trimmed = part.trim();
                if (trimmed.startsWith("CN=")) {
                    return trimmed.substring(trimmed.indexOf("=") + 1);
                }
            }
        } catch (Exception e) {
            return subject;
        }
        return subject;
    }

    private void saveToDatabase(String fileName, String signerName, boolean isValid) {
        ValidationLog log = new ValidationLog();
        log.setFileName(fileName);
        log.setSignerName(signerName);
        log.setValid(isValid);
        log.setValidationTime(LocalDateTime.now());
        repository.save(log);
    }

    public List<ValidationLog> getHistory() {
        return repository.findAllByOrderByValidationTimeDesc();
    }
}