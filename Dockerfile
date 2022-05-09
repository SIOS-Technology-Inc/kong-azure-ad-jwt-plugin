FROM kong:2.3.0

# Install middleware
USER root
RUN apk add --update nodejs npm python make g++
RUN apk add --update vim nano
ENV term xterm

# Install the js-pluginserver
RUN npm install --unsafe -g kong-pdk@0.3.0

# Install the plugin's pakcage
COPY ./plugins /usr/local/kong/js-plugins
COPY ./package-lock.json /usr/local/kong/js-plugins
COPY ./package.json /usr/local/kong/js-plugins
RUN npm --prefix /usr/local/kong/js-plugins ci --production /usr/local/kong/js-plugins

# Register the Kong plugins
ENV KONG_PLUGINSERVER_NAMES "js"
ENV KONG_PLUGINSERVER_JS_SOCKET "/usr/local/kong/js_pluginserver.sock"
ENV KONG_PLUGINSERVER_JS_START_CMD "/usr/bin/kong-js-pluginserver -v --plugins-directory /usr/local/kong/js-plugins"
ENV KONG_PLUGINSERVER_JS_QUERY_CMD "/usr/bin/kong-js-pluginserver --plugins-directory /usr/local/kong/js-plugins --dump-all-plugins"
ENV KONG_PLUGINS "bundled,oidc-for-azure-ad,oidc-for-azure-ad-b2c"
USER kong
