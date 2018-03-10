# See https://github.com/docker-library/php/blob/4677ca134fe48d20c820a19becb99198824d78e3/7.0/fpm/Dockerfile
FROM php:7.0-fpm

MAINTAINER Maxence POUTORD <maxence.poutord@gmail.com>

RUN apt-get update && apt-get install -y \
    git \
    unzip \
    libbz2-dev

RUN apt-get install -y libpng12-dev

# Install Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
RUN composer --version

# Set timezone
RUN rm /etc/localtime
RUN ln -s /usr/share/zoneinfo/Europe/Paris /etc/localtime
RUN "date"

# Type docker-php-ext-install to see available extensions
RUN docker-php-ext-install pdo pdo_mysql
RUN docker-php-ext-install bz2
RUN docker-php-ext-install exif
RUN docker-php-ext-install gd
RUN docker-php-ext-install mysqli
RUN docker-php-ext-install zip

# Pimcore 
RUN apt-get update && apt-get install -y zlib1g-dev libicu-dev g++
RUN docker-php-ext-configure intl
RUN docker-php-ext-install intl

RUN apt-get -y install libreoffice python-uno libreoffice-math xfonts-75dpi poppler-utils inkscape libxrender1 libfontconfig1 ghostscript

# Install wget
RUN apt-get -y install wget

# ZopfliPNG
RUN wget https://github.com/imagemin/zopflipng-bin/raw/master/vendor/linux/zopflipng -O /usr/local/bin/zopflipng 
RUN chmod 0755 /usr/local/bin/zopflipng

# PngCrush
RUN wget https://github.com/imagemin/pngcrush-bin/raw/master/vendor/linux/pngcrush -O /usr/local/bin/pngcrush
RUN chmod 0755 /usr/local/bin/pngcrush

# JPEGOptim
RUN wget https://github.com/imagemin/jpegoptim-bin/raw/master/vendor/linux/jpegoptim -O /usr/local/bin/jpegoptim
RUN chmod 0755 /usr/local/bin/jpegoptim

# PNGOut
RUN wget https://github.com/imagemin/pngout-bin/raw/master/vendor/linux/x64/pngout -O /usr/local/bin/pngout
RUN chmod 0755 /usr/local/bin/pngout

# Adv PNG
RUN wget https://github.com/imagemin/advpng-bin/raw/master/vendor/linux/advpng -O /usr/local/bin/advpng
RUN chmod 0755 /usr/local/bin/advpng

# Moz Jpeg
RUN wget https://github.com/imagemin/mozjpeg-bin/raw/master/vendor/linux/cjpeg -O /usr/local/bin/cjpeg
RUN chmod 0755 /usr/local/bin/cjpeg

# Exiftool
RUN apt-get install -y libimage-exiftool-perl

# ffmpeg
RUN wget https://johnvansickle.com/ffmpeg/builds/ffmpeg-git-64bit-static.tar.xz -O ffmpeg.tar.xz ;\
tar -Jxf ffmpeg*.tar.xz ;\
rm ffmpeg*.tar.xz ;\
mv ffmpeg-* /usr/local/ffmpeg ;\
ln -s /usr/local/ffmpeg/ffmpeg /usr/local/bin/ ;\
ln -s /usr/local/ffmpeg/ffprobe /usr/local/bin/ ;\
ln -s /usr/local/ffmpeg/qt-faststart /usr/local/bin/ ;\
ln -s /usr/local/ffmpeg/qt-faststart /usr/local/bin/qtfaststart ;

# imagick

RUN apt-get -y install \
            libmagickwand-dev \
        --no-install-recommends \
    && pecl install imagick \
    && docker-php-ext-enable imagick \
    && rm -r /var/lib/apt/lists/*

# install xdebug
RUN pecl install xdebug
RUN docker-php-ext-enable xdebug

VOLUME /root/.composer/cache
VOLUME /home/www-data/.composer/cache

ADD bin/docker-environment /usr/local/bin/
ADD etc/php.ini /usr/local/etc/php/conf.d/zz-magento.ini
ADD etc/mail.ini /usr/local/etc/php/conf.d/zz-mail.ini
ADD etc/php-xdebug.ini /usr/local/etc/php/conf.d/zz-xdebug-settings.ini
ADD etc/php-fpm.conf /usr/local/etc/

ENV PHP_MEMORY_LIMIT 4096M
ENV PHP_ENABLE_XDEBUG false
ENV DEBUG false
ENV UPDATE_UID_GID true
ENV PIMCORE_ROOT /var/www/symfony

RUN echo 'alias sf="php app/console"' >> ~/.bashrc
RUN echo 'alias sf3="php bin/console"' >> ~/.bashrc

WORKDIR /var/www/symfony

ENTRYPOINT ["/usr/local/bin/docker-environment"]
CMD ["php-fpm", "-F"]