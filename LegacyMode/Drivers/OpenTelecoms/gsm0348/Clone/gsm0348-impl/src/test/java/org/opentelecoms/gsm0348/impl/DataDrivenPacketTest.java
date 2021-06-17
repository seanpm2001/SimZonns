package org.opentelecoms.gsm0348.impl;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opentelecoms.gsm0348.api.PacketBuilder;
import org.opentelecoms.gsm0348.api.model.ResponsePacket;
import org.opentelecoms.gsm0348.impl.generated.Dataset;
import org.opentelecoms.gsm0348.impl.generated.TestCaseType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

public class DataDrivenPacketTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(DataDrivenPacketTest.class);

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
  }

  private Dataset loadDataset() throws JAXBException, IOException, SAXException, ParserConfigurationException {
    final String cfg = System.getProperty("dataset_packet.path");
    final File configurationFile = new File((cfg == null) ? "src/test/resources/Dataset0348.xml" : cfg);

    final JAXBContext ctx = JAXBContext.newInstance("org.opentelecoms.gsm0348.api.model:org.opentelecoms.gsm0348.impl.generated");
    final Unmarshaller u = ctx.createUnmarshaller();

    SchemaFactory sf = SchemaFactory.newInstance(javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
    Schema schema = sf.newSchema(new File("src/test/resources/Dataset0348.xsd"));

    u.setSchema(schema);

    return (Dataset) u.unmarshal(configurationFile);
  }

  @Test
  public void testAll() throws Exception {
    Dataset cfg = loadDataset();
    List<String> failed = new ArrayList<>();

    List<String> testNameList = new ArrayList<String>();
    for (TestCaseType testcase : cfg.getTestcase()) {
      final String name = testcase.getName();
      if (testNameList.contains(name)) {
        fail("Duplicated name found: " + name);
      }
      testNameList.add(name);
    }

    boolean passed = true;
    for (TestCaseType testcase : cfg.getTestcase()) {
      LOGGER.info("Running test id={} type={}", testcase.getName(), testcase.getType());
      PacketBuilder builder = new PacketBuilderImpl(testcase.getCardProfile().getValue());// PacketBuilderFactory.getInstance(testcase.getCardProfile());
      if (testcase.getType().equals("request")) {
        byte[] packet = null;
        try {
          packet = builder.buildCommandPacket(testcase.getData(), testcase.getCounter(), testcase.getCipheringKey(),
              testcase.getSignatureKey());
        } catch (Exception exception) {
          exception.printStackTrace();
          failed.add(testcase.getName());
          passed = false;
        }

        if (packet != null && !Arrays.equals(packet, testcase.getResult().getRequestResult())) {
          LOGGER.error("Name: {}", testcase.getName());
          LOGGER.error("Found: \t\t{}", Hex.toHexString(packet));
          LOGGER.error("Expected: \t{}", Hex.toHexString(testcase.getResult().getRequestResult()));
          failed.add(testcase.getName());
          passed = false;
        }
      } else {
        ResponsePacket packet = null;
        try {
          packet = builder.recoverResponsePacket(testcase.getData(), testcase.getCipheringKey(), testcase.getSignatureKey());
        } catch (Exception exception) {
          exception.printStackTrace();
          failed.add(testcase.getName());
          passed = false;
        }

        if (packet == null || !compareResponsePackets(testcase.getResult().getResponseResult().getValue(), packet)) {
          LOGGER.error("Name: {}", testcase.getName());
          LOGGER.error("Found: \t\t{}", packet);
          LOGGER.error("Expected: \t{}", testcase.getResult().getResponseResult().getValue());
          failed.add(testcase.getName());
          passed = false;
        }
      }

    }
    for (String fail: failed){
      LOGGER.error("Test {} failed", fail);
    }
    assertTrue(passed);
  }

  private boolean compareResponsePackets(ResponsePacket rp1, ResponsePacket rp2) {
    return rp1.equals(rp2);
  }

}
