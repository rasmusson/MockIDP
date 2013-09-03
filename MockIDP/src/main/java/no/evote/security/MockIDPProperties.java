package no.evote.security;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

public class MockIDPProperties {
	private static Properties properties = new Properties();

	private MockIDPProperties() {

	}

	static {
		try {
			FileInputStream fi = new FileInputStream("./MockIDP.properties");
			properties.load(fi);
			fi.close();
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static String getProperty(final String key) {
		return (String)properties.get(key);
	}

	public static String getSpConsumerUrl() {
		return (String)properties.get("spConsumerUrl");
	}

	public static String getAudienceUri() {
		return (String)properties.get("audienceUri");
	}

	public static String getIdpEntityId() {
		return "FakeIdP";
	}

}
