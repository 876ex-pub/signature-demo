
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import okhttp3.ConnectionPool;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

/**
 * Http client for accessing crypto exchange REST APIs.
 * 
 * Usage:
 * 
 * <code>
 * ApiClient apiClient = ApiClient.builder("https://api.876ex.com")
 *                                .apiKey("your-api-key", "your-api-secret")
 *                                .connectTimeout(5)
 *                                .readTimeout(3)
 *                                .keepAlive(60)
 *                                .setDebug(true)
 *                                .build();
 * OrderBean order = apiClient.get(OrderBean.class, "/v1/spots/orders/open", Map.of("symbol", "BTC_USDT"));
 * </code>
 * 
 * ApiClient instance is an expensive resource, it is thread-safe and should be
 * reused as global single instance.
 * 
 * Dependencies:
 * 
 * Add okhttp and jackson-databind to Maven dependencies:
 * 
 * <code>
 * <dependency>
 *     <groupId>com.squareup.okhttp3</groupId>
 *     <artifactId>okhttp</artifactId>
 *     <version>4.2.2</version>
 * </dependency>
 * <dependency>
 *     <groupId>com.fasterxml.jackson.core</groupId>
 *     <artifactId>jackson-databind</artifactId>
 *     <version>2.10.1</version>
 * </dependency>
 * </code>
 */
public class ApiClient {

	private final String endpoint;
	private final String host;
	private final String apiKey;
	private final byte[] apiSecret;
	private final boolean debug;

	private final ObjectMapper objectMapper;
	private OkHttpClient client;

	public static class Builder {

		String scheme;
		String host;
		int port;

		String apiKey;
		String apiSecret;

		int connectTimeout = 3;
		int readTimeout = 3;
		int keepAlive = 30;

		boolean debug = false;

		public static Builder builder(String apiEndpoint) {
			return new Builder(apiEndpoint);
		}

		/**
		 * Create builder with api endpoint. e.g. "https://api.876ex.com". NOTE:
		 * do not append any PATH.
		 *
		 * @param apiEndpoint The api endpoint.
		 */
		private Builder(String apiEndpoint) {
			try {
				URI uri = new URI(Objects.requireNonNull(apiEndpoint));
				if (!"https".equals(uri.getScheme()) && !"http".equals(uri.getScheme())) {
					throw new IllegalArgumentException("Invalid API endpoint: " + apiEndpoint);
				}
				if (uri.getPath() != null && !uri.getPath().isEmpty()) {
					throw new IllegalArgumentException("Invalid API endpoint: " + apiEndpoint);
				}
				this.scheme = uri.getScheme();
				this.host = uri.getHost().toLowerCase();
				this.port = uri.getPort();
			} catch (URISyntaxException e) {
				throw new IllegalArgumentException("Invalid API endpoint: " + apiEndpoint, e);
			}
		}

		public Builder apiKey(String apiKey, String apiSecret) {
			this.apiKey = Objects.requireNonNull(apiKey);
			this.apiSecret = Objects.requireNonNull(apiSecret);
			return this;
		}

		public Builder setDebug(boolean debug) {
			this.debug = debug;
			return this;
		}

		/**
		 * Set connection timeout in seconds.
		 */
		public Builder connectTimeout(int connectTimeoutInSeconds) {
			this.connectTimeout = connectTimeoutInSeconds;
			return this;
		}

		/**
		 * Set read timeout in seconds.
		 */
		public Builder readTimeout(int readTimeoutInSeconds) {
			this.readTimeout = readTimeoutInSeconds;
			return this;
		}

		/**
		 * Set keep-alive in seconds.
		 */
		public Builder keepAlive(int keepAliveInSeconds) {
			this.keepAlive = keepAliveInSeconds;
			return this;
		}

		public ApiClient build() {
			OkHttpClient client = new OkHttpClient.Builder()
					// set connect timeout:
					.connectTimeout(this.connectTimeout, TimeUnit.SECONDS)
					// set read timeout:
					.readTimeout(this.readTimeout, TimeUnit.SECONDS)
					// set connection pool:
					.connectionPool(new ConnectionPool(0, this.keepAlive, TimeUnit.SECONDS))
					// do not retry:
					.retryOnConnectionFailure(false).build();
			String endpoint = this.scheme + "://" + this.host;
			if (this.port != (-1)) {
				endpoint = endpoint + ":" + this.port;
			}
			return new ApiClient(this.apiKey, this.apiSecret, endpoint, this.host, client, this.debug);
		}
	}

	private ApiClient(String apiKey, String apiSecret, String endpoint, String host, OkHttpClient client,
			boolean debug) {
		this.apiKey = apiKey;
		this.apiSecret = apiSecret.getBytes(StandardCharsets.UTF_8);
		this.endpoint = endpoint;
		this.host = host;
		this.client = client;
		this.debug = debug;
		this.objectMapper = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
	}

	public <T> T get(Class<T> clazz, String path, Map<String, String> query) {
		Objects.requireNonNull(clazz);
		return request(clazz, null, "GET", path, query, null, null);
	}

	public <T> T get(TypeReference<T> ref, String path, Map<String, String> query) {
		Objects.requireNonNull(ref);
		return request(null, ref, "GET", path, query, null, null);
	}

	public <T> T post(Class<T> clazz, String path, Object body) {
		Objects.requireNonNull(clazz);
		return request(clazz, null, "POST", path, null, body, null);
	}

	public <T> T post(Class<T> clazz, String path, Object body, String uniqueId) {
		Objects.requireNonNull(clazz);
		return request(clazz, null, "POST", path, null, body, uniqueId);
	}

	public <T> T post(TypeReference<T> ref, String path, Object body) {
		Objects.requireNonNull(ref);
		return request(null, ref, "POST", path, null, body, null);
	}

	public <T> T post(TypeReference<T> ref, String path, Object body, String uniqueId) {
		Objects.requireNonNull(ref);
		return request(null, ref, "POST", path, null, body, uniqueId);
	}

	private <T> T request(Class<T> clazz, TypeReference<T> ref, String method, String path, Map<String, String> query,
			Object body, String uniqueId) {
		if (!path.startsWith("/")) {
			throw new IllegalArgumentException("Invalid path: " + path);
		}
		// build payload:
		StringBuilder payloadToSign = new StringBuilder(1024)
				// method:
				.append(method).append('\n')
				// host:
				.append(host).append('\n')
				// path:
				.append(path).append('\n');
		// query:
		String queryString = null;
		if (query != null) {
			List<String> paramList = new ArrayList<>();
			for (Map.Entry<String, String> entry : query.entrySet()) {
				paramList.add(entry.getKey() + "=" + entry.getValue());
			}
			Collections.sort(paramList);
			queryString = String.join("&", paramList);
			payloadToSign.append(queryString).append('\n');
		} else {
			payloadToSign.append('\n');
		}
		StringBuilder urlBuilder = new StringBuilder(64).append(this.endpoint).append(path);
		if (queryString != null) {
			urlBuilder.append('?').append(queryString);
		}
		final String url = urlBuilder.toString();

		// json body:
		String jsonBody;
		try {
			jsonBody = body == null ? ""
					: (body instanceof String ? (String) body : objectMapper.writeValueAsString(body));
		} catch (IOException ioe) {
			throw new RuntimeException(ioe);
		}

		Request.Builder requestBuilder = new Request.Builder().url(url);
		if ("POST".equals(method)) {
			requestBuilder.post(RequestBody.create(JSON, jsonBody));
		}

		final String timestamp = String.valueOf(System.currentTimeMillis());
		if (uniqueId == null || uniqueId.isEmpty()) {
			uniqueId = UUID.randomUUID().toString().replace("-", "");
		}

		// sign:
		if (apiKey != null) {
			// header:
			List<String> headerList = new ArrayList<>();
			headerList.add(HEADER_API_KEY + ": " + apiKey);
			headerList.add(HEADER_API_SIGNATURE_METHOD + ": " + SIGNATURE_METHOD);
			headerList.add(HEADER_API_SIGNATURE_VERSION + ": " + SIGNATURE_VERSION);
			headerList.add(HEADER_API_TIMESTAMP + ": " + timestamp);
			headerList.add(HEADER_API_UNIQUE_ID + ": " + uniqueId);
			Collections.sort(headerList);
			for (String header : headerList) {
				payloadToSign.append(header).append('\n');
			}

			requestBuilder.addHeader(HEADER_API_KEY, apiKey);
			requestBuilder.addHeader(HEADER_API_SIGNATURE_METHOD, SIGNATURE_METHOD);
			requestBuilder.addHeader(HEADER_API_SIGNATURE_VERSION, SIGNATURE_VERSION);
			requestBuilder.addHeader(HEADER_API_TIMESTAMP, timestamp);
			requestBuilder.addHeader(HEADER_API_UNIQUE_ID, uniqueId);

			// append body:
			payloadToSign.append(jsonBody);
			String payload = payloadToSign.toString();
			// sign:
			String sign = toHexString(
					hmacSha256(payload.getBytes(StandardCharsets.UTF_8), this.apiSecret));
			if (this.debug) {
				System.out.println("Payload: ----\n" + payload + "----\nSignature: " + sign);
			}
			requestBuilder.addHeader(HEADER_API_SIGNATURE, sign);
		}
		Request request = requestBuilder.build();
		try {
			return execute(clazz, ref, request);
		} catch (IOException e) {
			if (this.debug) {
				e.printStackTrace();
			}
			throw new UncheckedIOException(e);
		}
	}

	@SuppressWarnings("unchecked")
	private <T> T execute(Class<T> clazz, TypeReference<T> ref, Request request) throws IOException {
		if (this.debug) {
			System.out.println(request.method() + ": " + request.url().url());
		}
		try (Response response = this.client.newCall(request).execute()) {
			if (response.code() == 200) {
				try (ResponseBody body = response.body()) {
					String json = body.string();
					if ("null".equals(json)) {
						return null;
					}
					if (clazz == null) {
						return objectMapper.readValue(json, ref);
					}
					if (clazz == String.class) {
						return (T) json;
					}
					return objectMapper.readValue(json, clazz);
				}
			} else if (response.code() == 400) {
				try (ResponseBody body = response.body()) {
					String bodyString = body.string();
					if (this.debug) {
						System.err.println("Response 400: " + bodyString);
					}
					ApiErrorResponse err = objectMapper.readValue(bodyString, ApiErrorResponse.class);
					if (err == null || err.error == null) {
						throw new ApiException("UNKNOWN_ERROR", err == null ? null : err.data,
								err == null ? null : err.message);
					}
					throw new ApiException(err.error, err.data, err.message);
				}
			} else if (response.code() == 429) {
				// should not always happen:
				if (this.debug) {
					System.err.println("Response 429: RATE_LIMIT");
				}
				throw new ApiException("RATE_LIMIT");
			} else {
				throw new ApiException("OPERATION_FAILED", null, "Http error " + response.code());
			}
		}
	}

	private byte[] hmacSha256(byte[] data, byte[] key) {
		SecretKey skey = new SecretKeySpec(key, "HmacSHA256");
		Mac mac;
		try {
			mac = Mac.getInstance("HmacSHA256");
			mac.init(skey);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
		mac.update(data);
		return mac.doFinal();
	}

	private String toHexString(byte[] b) {
		StringBuilder sb = new StringBuilder(b.length * 2);
		for (byte x : b) {
			int hi = (x & 0xf0) >> 4;
			int lo = x & 0x0f;
			sb.append(HEX_CHARS[hi]);
			sb.append(HEX_CHARS[lo]);
		}
		return sb.toString().trim();
	}

	private static final String HEADER_API_KEY = "API-KEY";
	private static final String HEADER_API_SIGNATURE = "API-SIGNATURE";
	private static final String HEADER_API_SIGNATURE_METHOD = "API-SIGNATURE-METHOD";
	private static final String HEADER_API_SIGNATURE_VERSION = "API-SIGNATURE-VERSION";
	private static final String HEADER_API_TIMESTAMP = "API-TIMESTAMP";
	private static final String HEADER_API_UNIQUE_ID = "API-UNIQUE-ID";

	private static final String SIGNATURE_METHOD = "HmacSHA256";
	private static final String SIGNATURE_VERSION = "1";

	private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

	private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

	public static class ApiException extends RuntimeException {

		public final String error;
		public final String data;

		public ApiException(String error) {
			super(error.toString());
			this.error = error;
			this.data = null;
		}

		public ApiException(String error, String data) {
			super(error.toString());
			this.error = error;
			this.data = data;
		}

		public ApiException(String error, String data, String message) {
			super(message);
			this.error = error;
			this.data = data;
		}
	}

	public static class ApiErrorResponse {

		public String error;
		public String data;
		public String message;

	}

	public static void main(String args[]){
		ApiClient apiClient = ApiClient.Builder.builder("https://XXXXXX").apiKey("xxx","xxx").build();
		String response = apiClient.get(String.class,"/v1/market/fex", null);
		System.out.println(response);
	}
}
