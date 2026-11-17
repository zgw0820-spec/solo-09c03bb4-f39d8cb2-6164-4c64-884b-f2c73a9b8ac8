FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/nginx.conf
COPY reload-watcher.sh /reload-watcher.sh
RUN chmod +x /reload-watcher.sh \
  && mkdir -p /usr/share/nginx/html \
  && printf '<h1>demo.internal intranet site</h1>\n' > /usr/share/nginx/html/index.html

# 容器入口：启动 nginx 并看守重载请求目录
CMD ["/reload-watcher.sh"]
