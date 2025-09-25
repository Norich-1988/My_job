################################################################################
FROM registry.it-bfg.ru/vdi/hvdi-rc:250530 AS build

COPY ./server /svdi/server

RUN cd /svdi/server/src/vdi/locale/ru/LC_MESSAGES \
  && msgfmt djangojs.po -o djangojs.mo \
  && msgfmt django.po -o django.mo \
  && cd /svdi/server/src/vdi/locale/en/LC_MESSAGES \
  && msgfmt djangojs.po -o djangojs.mo \
  && msgfmt django.po -o django.mo

COPY ./docker/lighttpd.conf /etc/lighttpd/lighttpd.conf
COPY ./docker/entrypoint /usr/local/bin/entrypoint
COPY ./docker/server.pem /etc/lighttpd/server.pem
RUN chmod +x /usr/local/bin/entrypoint

RUN mkdir -p /svol/log  /svol/kerberos /svol/license \
  && mv /var/lib/postgresql /svol \
  && ln -s /svol/postgresql /var/lib/postgresql \
  && ln -s /svol/log /svdi/server/log

COPY ./docker/gen_key.py /svol/license

ARG IMA_KEY
RUN echo "$IMA_KEY" > /key.pem
RUN find / -regex '.*\(\.so\.[^/]*\|\.so\)' !  -perm /111 -type f  -exec evmctl ima_sign -n --sigfile --portable --hashalgo sha512 \
                                                                                         --key /key.pem \{} \; > /dev/null 2>&1
RUN find / \( -path /drone -o -path /hvs -o -path /etc/portage -o -path /usr/portage -o -path /var/db/pkg -o -path /var/tmp/portage \) \
  -prune -o \( -xdev -type f -executable -exec evmctl ima_sign -n --sigfile --portable --hashalgo sha512 --key /key.pem \{} \; \) > /dev/null 2>&1
RUN rm /key.p*

###############################################################################

FROM scratch

COPY --from=build / /
ENTRYPOINT ["entrypoint"]
