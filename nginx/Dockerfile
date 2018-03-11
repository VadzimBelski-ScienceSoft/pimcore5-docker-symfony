FROM nginx:stable-alpine

MAINTAINER Vadzim Belski <belski@scnsoft.com>

ADD nginx.conf /etc/nginx/nginx.conf
ADD symfony.conf /etc/nginx/conf.d/symfony.conf

RUN rm -rf /etc/nginx/conf.d/default.conf

RUN echo "upstream php-pimcore5 { server php:9000; }" > /etc/nginx/conf.d/upstream.conf

# ensure www-data user exists
RUN set -x \
    && addgroup -g 82 -S www-data \
    && adduser -u 82 -D -S -G www-data www-data

RUN apk --no-cache add shadow && \
        usermod -u 1000 www-data

CMD ["nginx"]

EXPOSE 80
EXPOSE 443
