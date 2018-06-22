package com.aek56.microservice.auth.config;

import java.nio.charset.Charset;
import java.util.Iterator;
import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

@Configuration
public class RestConfiguration {

	@Bean
	@ConditionalOnMissingBean({ RestOperations.class, RestTemplate.class })
	public RestOperations restOperations() {
		SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
		requestFactory.setReadTimeout(5000);
		requestFactory.setConnectTimeout(5000);

		RestTemplate restTemplate = new RestTemplate(requestFactory);

		// 使用 utf-8 编码集的 conver 替换默认的 conver（默认的 string conver 的编码集为"ISO-8859-1"）
		List<HttpMessageConverter<?>> messageConverters = restTemplate.getMessageConverters();
		Iterator<HttpMessageConverter<?>> iterator = messageConverters.iterator();
		while (iterator.hasNext()) {
			HttpMessageConverter<?> converter = iterator.next();
			if (converter instanceof StringHttpMessageConverter) {
				iterator.remove();
			}
		}
		messageConverters.add(new StringHttpMessageConverter(Charset.forName("UTF-8")));

		return restTemplate;
	}
}
