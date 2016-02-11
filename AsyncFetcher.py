import time
import thread
import httplib
import socket
import select
import os
from collections import defaultdict
import Queue
from StringIO import StringIO
import random


# ------------------------------------------------------------------------------------
class ERROR:
	CONNECTION_FAILED = -100
	CONNECTION_DROPED = -101
	MAX_QUEUE_SIZE = -110
	MAX_HOST_CONNECTIONS = - 111


# ------------------------------------------------------------------------------------
class SETTINGS:
	# After INACTIVE_TIMEOUT after last received data
	# connection will be removed from pool.
	INACTIVE_TIMEOUT = 3 * 60

	# Timeout for connecting to host. Host connections are blocking - do not use too big value.
	CONNECTION_TIMEOUT = 4

	# Number of retries if failure.
	DEFAULT_ATTEMPTS = 3

	# Send error response if too many requests incoming.
	MAX_QUEUE_SIZE = 1000

	# If we processing request too long - consider it dead
	REQUEST_PROCESSING_TIMEOUT = 2 * 60

	# Time to cache dns responses, seconds
	DNS_CACHE_TIME = 60 * 60

	# Time to cache dns errors
	DNS_FAIL_CACHE_TIME = 2 * 60

	# Maximum number of connections per host
	MAX_CONNECTIONS_PER_HOST = 300

# ------------------------------------------------------------------------------------
def LOG_DEBUG_DEV(msg):
	#print '[DEBUG]', msg
	pass

# ------------------------------------------------------------------------------------
def LOG_WARNING(msg):
	print '[WARNING]', msg


# ------------------------------------------------------------------------------------
class _StrSocket(object):
	def __init__(self, response_str):
		self._file = StringIO(response_str)
	def makefile(self, *args, **kwargs):
		return self._file


# ------------------------------------------------------------------------------------
def _buildRequest(host, method, query, data):
	request = '{method} http://{host}{query} HTTP/1.1\r\n'\
			'Host: {host}\r\n'\
			'Connection: Keep-Alive\r\n'.format(method=method, query=query, host=host)
	if data is not None:
		request += 'Content-Type: application/x-www-form-urlencoded\r\n'\
					'Content-Length: {len}\r\n'.format(len=str(len(data)))
	request += '\r\n'
	if data is not None:
		request += data
	return request


# ------------------------------------------------------------------------------------
class _Connection(object):

	# ------------------------------------------------------------------------------------
	def __init__(self, host, ep, dnsResolver):
		self.host = host
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		host = host.split(':')
		if len(host) == 0:
			raise Exception("wrong host")
		elif len(host) == 1:
			host.append(80)
		host[1] = int(host[1])
		host[0] = dnsResolver.resolve(host[0])
		host = tuple(host[:2])

		self.sock.settimeout(SETTINGS.CONNECTION_TIMEOUT)

		self.sock.setblocking(0)

		ep.register(self.sock.fileno(), select.EPOLLOUT)

		try:
			self.sock.connect(host)
		except socket.error as e:
			if e.errno != 115:
				self.sock.close()
				raise e

		self.clear()
		self.lastResponse = time.time()
		self.state = 'connecting'

	# ------------------------------------------------------------------------------------
	def clear(self):
		self.__buffer = ''
		self.request = None
		self.__req = None

	# ------------------------------------------------------------------------------------
	def fileno(self):
		return self.sock.fileno()

	# ------------------------------------------------------------------------------------
	def sendRequest(self, httpRequest):
		LOG_DEBUG_DEV('send request')
		self.request = httpRequest
		req = _buildRequest(self.host, httpRequest.method, httpRequest.query, httpRequest.data)
		if self.state == 'connecting':
			LOG_DEBUG_DEV('connecting')
			self.__req = req
		else:
			res = self.sock.send(req)
			LOG_DEBUG_DEV('sending: %s' % str(res))

	# ------------------------------------------------------------------------------------
	def onConnected(self):
		LOG_DEBUG_DEV('on connected')
		self.state = 'connected'
		self.lastResponse = time.time()
		if self.__req is not None:
			res = self.sock.send(self.__req)
			LOG_DEBUG_DEV('sending: %s' % str(res))
			self.__req = None

	# ------------------------------------------------------------------------------------
	def processResponse(self):
		LOG_DEBUG_DEV('process response')
		resp = self.sock.recv(1024)
		if len(resp) > 0:
			self.lastResponse = time.time()
		self.__buffer += resp
		source = _StrSocket(self.__buffer)
		response = httplib.HTTPResponse(source)
		response.begin()
		status = response.status
		data = response.read()
		LOG_DEBUG_DEV('response parsed')
		return (status, data, self.request)

	# ------------------------------------------------------------------------------------
	def isActive(self):
		return time.time() < self.lastResponse + SETTINGS.INACTIVE_TIMEOUT


# ------------------------------------------------------------------------------------
class _ConnectionManager(object):

	# ------------------------------------------------------------------------------------
	def __init__(self, dnsResolver):
		self.__connections = {} # host -> list of connections
		self.__dnsResolver = dnsResolver

	# ------------------------------------------------------------------------------------
	def getConnection(self, host, ep):
		hostConnections = self.__connections.get(host, None)
		if hostConnections is None:
			return _Connection(host, ep, self.__dnsResolver)
		conn = hostConnections[0]
		del hostConnections[0]
		if len(hostConnections) == 0:
			del self.__connections[host]
		return conn

	def getWaitingConnectionsNum(self, host):
		return len(self.__connections.get(host, []))

	# ------------------------------------------------------------------------------------
	def returnConnection(self, connection):
		connection.clear()
		self.__connections.setdefault(connection.host, []).append(connection)

	# ------------------------------------------------------------------------------------
	def removeOldConnections(self, ep):
		newConnections = {}
		for host, connections in self.__connections.iteritems():
			goodConnections = []
			for conn in connections:
				if conn.isActive():
					goodConnections.append(conn)
				else:
					try:
						ep.unregister(conn.sock.fileno())
					except IOError:
						pass
			if len(goodConnections) > 0:
				newConnections[host] = goodConnections
		self.__connections = newConnections

	# ------------------------------------------------------------------------------------
	def removeConnection(self, fno):
		newConnections = {}
		for host, connections in self.__connections.iteritems():
			goodConnections = []
			for conn in connections:
				if conn.fileno() != fno:
					goodConnections.append(conn)
			if len(goodConnections) > 0:
				newConnections[host] = goodConnections
		self.__connections = newConnections

	# ------------------------------------------------------------------------------------
	def printStatus(self):
		print 'connection-manager:', len(self.__connections)
		for h in self.__connections:
			print h, len(self.__connections[h])

	# ------------------------------------------------------------------------------------
	def getStatusDict(self):
		status = {}
		for h, c in self.__connections.iteritems():
			status['waiting_host_connections.%s' % h] = len(c)
		return status


# ------------------------------------------------------------------------------------
class _DnsCachingResolver(object):

	# ------------------------------------------------------------------------------------
	def __init__(self):
		self.__cache = {} # hostname => (time, [ip1, ip2, ... ])

	# ------------------------------------------------------------------------------------
	def resolve(self, hostname):
		currTime = time.time()
		cachedTime, ips = self.__cache.get(hostname, (0, []))
		timePassed = currTime - cachedTime
		if (timePassed > SETTINGS.DNS_CACHE_TIME) or (not ips and timePassed > SETTINGS.DNS_FAIL_CACHE_TIME):
			prevIps = ips
			ips = self.__doResolve(hostname)
			if not ips:
				ips = prevIps
			self.__cache[hostname] = (currTime, ips)
		if len(self.__cache) > 10000:
			self.__cache = {}
		return None if not ips else random.choice(ips)

	# ------------------------------------------------------------------------------------
	def __doResolve(self, hostname):
		LOG_DEBUG_DEV('resolving %s' % hostname)
		try:
			ips = socket.gethostbyname_ex(hostname)[2]
		except socket.gaierror:
			LOG_WARNING('failed to resolve host %s' % hostname)
			ips = []
		return ips


# ------------------------------------------------------------------------------------
class HttpRequest(object):
	def __init__(self, host, method, query, data, callback):
		self.host = host
		self.method = method
		self.query = query
		self.data = data
		self.callback = callback
		self.attempts = SETTINGS.DEFAULT_ATTEMPTS

	# ------------------------------------------------------------------------------------
	def signature(self):
		return str(self.host) + '\n' + str(self.method) + '\n' + str(self.query) + '\n' + str(self.data)


# ------------------------------------------------------------------------------------
class AsyncFetcher(object):

	# ------------------------------------------------------------------------------------
	def __init__(self):
		self.__epoll = select.epoll()
		self.__requestQueue = Queue.Queue()
		self.__responseQueue = Queue.Queue()
		self.__connections = {} # fileno => http connection
		self.__dnsResolver = _DnsCachingResolver()
		self.__connectionManager = _ConnectionManager(self.__dnsResolver)
		self.pipeToThread = os.pipe()
		self.pipeToMain = os.pipe()
		self.__currentRequests = {}
		self.__connectionsNumPerHost = defaultdict(int)
		thread.start_new_thread(self.__workerThread, ())
		thread.start_new_thread(self.__mainThread, ())

	# ------------------------------------------------------------------------------------
	def fetch(self, request):
		LOG_DEBUG_DEV('fetch request')
		if self.__requestQueue.qsize() > SETTINGS.MAX_QUEUE_SIZE or\
				self.__responseQueue.qsize() > SETTINGS.MAX_QUEUE_SIZE:
			try:
				LOG_DEBUG_DEV('max queue size')
				request.callback(ERROR.MAX_QUEUE_SIZE, '', request)
			except Exception as e:
				print '[ERROR]', e
			return

		currentRequests = self.__currentRequests.get(request.signature(), None)
		if currentRequests is not None:
			LOG_DEBUG_DEV('request already in flight')
			currentRequests.append(request)
			return

		LOG_DEBUG_DEV('added request to queue')
		self.__requestQueue.put(request)
		self.__currentRequests[request.signature()] = [int(time.time()), request]
		os.write(self.pipeToThread[1], '\n')

	# ------------------------------------------------------------------------------------
	def onTimer(self, timerID, userData):
		self.__checkTimeouts()

	# ------------------------------------------------------------------------------------
	def processCallbacks(self, fd = None):
		LOG_DEBUG_DEV('process callbacks')
		pipeIn = self.pipeToMain[0]
		os.read(pipeIn, 1)
		while not self.__responseQueue.empty():
			status, data, request = self.__responseQueue.get()
			LOG_DEBUG_DEV(status)
			currentRequests = self.__currentRequests.pop(request.signature(), None)
			if currentRequests is None:
				currentRequests = [request]
			else:
				currentRequests = currentRequests[1:]

			for req in currentRequests:
				try:
					req.callback(status, data, req)
				except Exception as e:
					print '[ERROR] callback error:', e

	# Remove requests that lives too long
	# ------------------------------------------------------------------------------------
	def __checkTimeouts(self):
		for k in self.__currentRequests.keys():
			ts = self.__currentRequests.get(k, (0, 0))[0]
			if ts is not None and ts + SETTINGS.REQUEST_PROCESSING_TIMEOUT < time.time():
				del self.__currentRequests[k]

	# ------------------------------------------------------------------------------------
	def __mainThread(self):
		pipeIn = self.pipeToMain[0]
		while True:
			os.read(pipeIn, 1)
			while not self.__responseQueue.empty():
				status, data, request = self.__responseQueue.get()
				request.callback(status, data, request)

	# ------------------------------------------------------------------------------------
	def __workerThread(self):
		pipeIn = self.pipeToThread[0]
		self.__epoll.register(pipeIn, select.EPOLLIN)
		last10SecondsTime = time.time()
		while True:
			try:
				events = self.__epoll.poll(0.2)
				for fileno, event in events:
					if fileno == pipeIn:
						os.read(pipeIn, 1)
						while not self.__requestQueue.empty():
							request = self.__requestQueue.get()
							self.__processRequest(request)
					elif fileno in self.__connections:
						self.__processIncoming(fileno)
					else:
						LOG_DEBUG_DEV('event in unknown descr: %d' % fileno)
						self.__epoll.unregister(fileno)
						self.__connectionManager.removeConnection(fileno)

				ctime = time.time()
				for fd in self.__connections.keys():
					conn = self.__connections[fd]
					if (conn.state == 'connecting' and conn.lastResponse + SETTINGS.CONNECTION_TIMEOUT < ctime) or \
							(conn.state == 'connected' and conn.lastResponse + SETTINGS.INACTIVE_TIMEOUT < ctime):
						if request.attempts <= 1:
							self.__publishResponse(ERROR.CONNECTION_FAILED, '', conn.request)
						else:
							request.attempts -= 1
							self.__processRequest(request)
						self.__epoll.unregister(fd)
						del self.__connections[fd]
						self.__connectionsNumPerHost[conn.host] -= 1

				if time.time() > last10SecondsTime + 10.0:
					last10SecondsTime = time.time()
					self.__connectionManager.removeOldConnections(self.__epoll)
					self.__connectionsNumPerHost = defaultdict(int)
					for conn in self.__connections:
						self.__connectionsNumPerHost[conn.host] += 1
			except Exception as e:
				print '[ERROR]', e


	# ------------------------------------------------------------------------------------
	def __publishResponse(self, status, data, request):
		LOG_DEBUG_DEV('publishing response %d' % status)
		self.__responseQueue.put((status, data, request))
		os.write(self.pipeToMain[1], '\n')

	# ------------------------------------------------------------------------------------
	def __processRequest(self, request):
		LOG_DEBUG_DEV('process request')
		try:
			if self.__connectionsNumPerHost[request.host] >= SETTINGS.MAX_CONNECTIONS_PER_HOST and \
					self.__connectionManager.getWaitingConnectionsNum(request.host) == 0:
				self.__publishResponse(ERROR.MAX_HOST_CONNECTIONS, '', request)
				return
			conn = self.__connectionManager.getConnection(request.host, self.__epoll)
		except (socket.gaierror, socket.timeout, socket.error):
			if request.attempts <= 1:
				self.__publishResponse(ERROR.CONNECTION_FAILED, '', request)
			else:
				request.attempts -= 1
				self.__processRequest(request)
			return
		fno = conn.fileno()
		self.__connections[fno] = conn
		self.__connectionsNumPerHost[conn.host] += 1
		conn.sendRequest(request)

	# ------------------------------------------------------------------------------------
	def __processIncoming(self, fileno):
		LOG_DEBUG_DEV('process incoming')
		conn = self.__connections[fileno]
		try:
			if conn.state == 'connecting':
				self.__epoll.unregister(conn.sock.fileno())
				self.__epoll.register(conn.sock.fileno(), select.EPOLLIN)
				conn.onConnected()
				return
			res = conn.processResponse()
		except (httplib.IncompleteRead, socket.error):
			return
		except httplib.BadStatusLine:
			self.__epoll.unregister(fileno)
			del self.__connections[fileno]
			self.__connectionsNumPerHost[conn.host] -= 1
			if conn.request.attempts <= 1:
				self.__publishResponse(ERROR.CONNECTION_DROPED, '', conn.request)
			else:
				conn.request.attempts -= 1
				self.__processRequest(conn.request)
			return

		status, data, callback = res
		self.__publishResponse(status, data, callback)
		self.__connectionManager.returnConnection(conn)
		del self.__connections[fileno]
		self.__connectionsNumPerHost[conn.host] -= 1

	# ------------------------------------------------------------------------------------
	def getRequestQueueSize(self):
		return self.__requestQueue.qsize()

	# ------------------------------------------------------------------------------------
	def getResponseQueueSize(self):
		return self.__responseQueue.qsize()

	# ------------------------------------------------------------------------------------
	def getConnectionsNumber(self):
		return len(self.__connections)

	# ------------------------------------------------------------------------------------
	def printStatus(self):
		print '\n === AsyncFetcher status ==='
		print 'connections:', len(self.__connections)
		print 'requests-queue:', self.__requestQueue.qsize()
		print 'response-queue:', self.__responseQueue.qsize()
		self.__connectionManager.printStatus()
		print ''

	def getStatusDict(self):
		status = {
			'requests_queue': self.__requestQueue.qsize(),
			'response_queue': self.__responseQueue.qsize(),
			'connections': len(self.__connections),
		}
		for k, v in self.__connectionsNumPerHost.iteritems():
			status['host_connections.%s' % k] = v
		status.update(self.__connectionManager.getStatusDict())
		return status

#   Usage sample
# ====================================================================================

# ------------------------------------------------------------------------------------
def sampleCallback(status, data, request):
	print 'fetched:', status, len(data)
	print data

# ------------------------------------------------------------------------------------
if __name__ == '__main__':
	fetcher = AsyncFetcher()
	while True:
		fetcher.fetch(HttpRequest('google.com:80', 'GET', '/', None, sampleCallback))
		time.sleep(4.0)