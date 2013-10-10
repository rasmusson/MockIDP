package no.steras.mockidp;

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
			String propertiesPath = System.getenv("MOCKIDP_PROPERTIES");
			if (propertiesPath == null) {
				propertiesPath = "./MockIDP.properties";
			}
			
			FileInputStream fi = new FileInputStream(propertiesPath);
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

	public static String getIdpEntityId() {
		return "FakeIdP";
	}

	public static String getSpEntityId() {
		return (String)properties.get("spEntityId");
	}

	public static String getSpMetadataLocation() {
		return (String)properties.get("spMetadataLocation");
	}

}
