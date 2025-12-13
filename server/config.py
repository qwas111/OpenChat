# gunicorn_config.py
import multiprocessing

# 绑定地址和端口
bind = "0.0.0.0:4000"

# 工作进程数 (推荐设置为 CPU 核心数 * 2 + 1)
workers = multiprocessing.cpu_count()

# 工作线程数
threads = 4

# 工作模式 (gevent 或 sync)
worker_class = "gevent"

# 最大客户端连接数
worker_connections = 1000

# 超时时间 (秒)
timeout = 120

# 保持活动连接
keepalive = 20

# 日志配置
accesslog = "gunicorn_access.log"
errorlog = "gunicorn_error.log"
loglevel = "info"

# 最大请求数 (防止内存泄漏)
max_requests = 1000
max_requests_jitter = 50

# 进程名
proc_name = "openchat"