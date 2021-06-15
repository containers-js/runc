import execa from 'execa'
import fsp from 'fs/promises'
import tempy from 'tempy'
import {Process} from './runtimeSpec' // TODO: replace with @containers/runtime-spec after publish

export interface GlobalOptions {
  /**
   * Path to `runc` binary
   *
   * @default 'runc'
   */
  runcCommand?: string
  /**
   * Enable debug output for logging
   */
  debug?: boolean
  /**
   * The log file path where internal debug information is written
   */
  log?: string
  /**
   * The format used by logs
   *
   * @default 'text'
   */
  logFormat?: 'text' | 'json'
  /**
   * Root directory for storage of container state (this should be located in a tmpfs)
   *
   * @default '/run/runc'
   */
  root?: string
  /**
   * Path to the criu binary used for checkpoint and restore
   *
   * @default 'criu'
   */
  criu?: string
  /**
   * Enable systemd cgroup support, expected to be of form `slice:prefix:name`, e.g. `system.slice:runc:434234`
   */
  systemdCgroup?: string
  /**
   * Ignore cgroup permission errors
   *
   * @default 'auto'
   */
  rootless?: boolean | 'auto'
}

// See: https://github.com/opencontainers/runc/blob/master/libcontainer/container.go
export interface Container {
  id?: string
  pid?: number
  status?: 'created' | 'running' | 'pausing' | 'paused' | 'stopped' | 'unknown'
  bundle?: string
  rootfs?: string
  created?: string
  owner?: string
  annotations?: Record<string, string>
}

export interface CheckpointOptions {
  /** path for saving criu image files */
  imagePath?: string
  /** path for saving work files and logs */
  workPath?: string
  /** path for previous criu image files in pre-dump */
  parentPath?: string
  /** leave the process running after checkpointing */
  leaveRunning?: boolean
  /** allow open tcp connections */
  tcpEstablished?: boolean
  /** allow external unix sockets */
  extUnixSk?: boolean
  /** allow shell jobs */
  shellJob?: boolean
  /** use userfaultfd to lazily restore memory pages */
  lazyPages?: boolean
  /** criu writes \0 to this FD once lazy-pages is ready (default: -1) */
  statusFd?: number
  /** ADDRESS:PORT of the page server */
  pageServer?: string
  /** handle file locks, for safety */
  fileLocks?: boolean
  /** dump container's memory information only, leave the container running after this */
  preDump?: boolean
  /** cgroups mode: 'soft' (default), 'full' and 'strict' */
  manageCgroupsMode?: 'soft' | 'full' | 'strict'
  /** create a namespace, but don't restore its properties */
  emptyNs?: string
  /** enable auto deduplication of memory images */
  autoDedup?: boolean
}

export interface CreateOptions {
  /** path to an AF_UNIX socket which will receive a file descriptor referencing the master end of the console's pseudoterminal */
  consoleSocket?: string
  /** specify the file to write the process id to */
  pidFile?: string
  /** do not use pivot root to jail process inside rootfs.  This should be used whenever the rootfs is on top of a ramdisk */
  noPivot?: boolean
  /** do not create a new session keyring for the container.  This will cause the container to inherit the calling processes session key */
  noNewKeyring?: boolean
  /** Pass N additional file descriptors to the container (stdio + $LISTEN_FDS + N in total) (default: 0) */
  preserveFDs?: number
}

export interface DeleteOptions {
  /** Forcibly delete the container if it is still running (uses SIGKILL) */
  force?: boolean
}

export interface ExecOptions {
  /** path to an AF_UNIX socket which will receive a file descriptor referencing the master end of the console's pseudoterminal */
  consoleSocket?: string
  /** specify the file to write the process id to */
  pidFile?: string
  /** Pass N additional file descriptors to the container (stdio + $LISTEN_FDS + N in total) (default: 0) */
  preserveFDs?: number
}

export interface KillOptions {
  /** send the specified signal to all processes inside the container */
  all?: boolean
}

export interface RestoreOptions {
  /** path to an AF_UNIX socket which will receive a file descriptor referencing the master end of the console's pseudoterminal */
  consoleSocket?: string
  /** path to criu image files for restoring */
  imagePath?: string
  /** path for saving work files and logs */
  workPath?: string
  /** allow open tcp connections */
  tcpEstablished?: boolean
  /** allow external unix sockets */
  extUnixSk?: boolean
  /** allow shell jobs */
  shellJob?: boolean
  /** handle file locks, for safety */
  fileLocks?: boolean
  /** cgroups mode: 'soft' (default), 'full' and 'strict' */
  manageCgroupsMode?: 'soft' | 'full' | 'strict'
  /** path to the root of the bundle directory */
  bundleValue?: string
  /** detach from the container's process */
  detach?: boolean
  /** specify the file to write the process id to */
  pidFile?: string
  /** disable the use of the subreaper used to reap reparented processes */
  noSubreaper?: boolean
  /** do not use pivot root to jail process inside rootfs.  This should be used whenever the rootfs is on top of a ramdisk */
  noPivot?: boolean
  /** create a namespace, but don't restore its properties */
  emptyNs?: string
  /** enable auto deduplication of memory images */
  autoDedup?: boolean
  /** use userfaultfd to lazily restore memory pages */
  lazyPages?: boolean
}

export interface RunOptions extends CreateOptions {
  detach?: boolean
  noSubreaper?: boolean
}

export class RunC {
  command: string
  globalOptions: string[] = []

  constructor(options: GlobalOptions = {}) {
    this.command = options.runcCommand ?? 'runc'
    if (options.debug) this.globalOptions.push('--debug')
    if (options.log) this.globalOptions.push('--log', options.log)
    if (options.logFormat) this.globalOptions.push('--log-format', options.logFormat)
    if (options.root) this.globalOptions.push('--root', options.root)
    if (options.criu) this.globalOptions.push('--criu', options.criu)
    if (options.systemdCgroup) this.globalOptions.push('--systemd-cgroup', options.systemdCgroup)
    if (options.rootless != null) this.globalOptions.push('--rootless', options.rootless.toString())
  }

  async checkpoint(id: string, options: CheckpointOptions = {}) {
    const args: string[] = []

    if (options.imagePath) args.push('--image-path', options.imagePath)
    if (options.workPath) args.push('--work-path', options.workPath)
    if (options.parentPath) args.push('--parent-path', options.parentPath)
    if (options.leaveRunning) args.push('--leave-running')
    if (options.tcpEstablished) args.push('--tcp-established')
    if (options.extUnixSk) args.push('--ext-unix-sk')
    if (options.shellJob) args.push('--shell-job')
    if (options.lazyPages) args.push('--lazy-pages')
    if (options.statusFd) args.push('--status-fd', options.statusFd.toString())
    if (options.pageServer) args.push('--page-server', options.pageServer)
    if (options.fileLocks) args.push('--file-locks')
    if (options.preDump) args.push('--pre-dump')
    if (options.manageCgroupsMode) args.push('--manage-cgroups-mode', options.manageCgroupsMode)
    if (options.emptyNs) args.push('--empty-ns', options.emptyNs)
    if (options.autoDedup) args.push('--auto-dedupe')

    await execa(this.command, [...this.globalOptions, 'checkpoint', ...args, id])
  }

  async create(id: string, bundle: string, options: CreateOptions = {}) {
    const args = ['--bundle', bundle]

    if (options.consoleSocket) args.push('--console-socket', options.consoleSocket)
    if (options.pidFile) args.push('--pid-file', options.pidFile)
    if (options.noPivot) args.push('--no-pivot')
    if (options.noNewKeyring) args.push('--no-new-keyring')
    if (options.preserveFDs) args.push('--preserve-fds', options.preserveFDs.toString())

    await execa(this.command, [...this.globalOptions, 'create', ...args, id], {stdio: 'inherit'})
  }

  async delete(id: string, options: DeleteOptions = {}) {
    const args = []
    if (options.force) args.push('--force')
    await execa(this.command, [...this.globalOptions, 'delete', ...args, id])
  }

  async exec(id: string, spec: Process, options: ExecOptions) {
    const specFile = await tempy.write(JSON.stringify(spec), {extension: 'json'})
    try {
      const args = ['--process', specFile]

      if (options.consoleSocket) args.push('--console-socket', options.consoleSocket)
      if (options.pidFile) args.push('--pid-file', options.pidFile)
      if (options.preserveFDs) args.push('--preserve-fds', options.preserveFDs.toString())

      return await execa(this.command, [...this.globalOptions, 'exec', ...args, id])
    } catch (err) {
      throw err
    } finally {
      await fsp.unlink(specFile)
    }
  }

  async kill(id: string, signal: string, options: KillOptions = {}) {
    const args = []
    if (options.all) args.push('--all')
    await execa(this.command, [...this.globalOptions, 'kill', ...args, id, signal])
  }

  async list(): Promise<Container[]> {
    const res = await execa(this.command, [...this.globalOptions, 'list', '--format=json'])

    if (res.stdout === 'null') {
      return []
    }

    return JSON.parse(res.stdout)
  }

  async pause(id: string) {
    await execa(this.command, [...this.globalOptions, 'pause', id])
  }

  async resume(id: string) {
    await execa(this.command, [...this.globalOptions, 'resume', id])
  }

  async restore(id: string, options: RestoreOptions = {}) {
    const args: string[] = []

    if (options.consoleSocket) args.push('--console-socket', options.consoleSocket)
    if (options.imagePath) args.push('--image-path', options.imagePath)
    if (options.workPath) args.push('--work-path', options.workPath)
    if (options.tcpEstablished) args.push('--tcp-established')
    if (options.extUnixSk) args.push('--ext-unix-sk')
    if (options.shellJob) args.push('--shell-job')
    if (options.fileLocks) args.push('--file-locks')
    if (options.manageCgroupsMode) args.push('--manage-cgroups-mode', options.manageCgroupsMode)
    if (options.bundleValue) args.push('--bundle-value', options.bundleValue)
    if (options.detach) args.push('--detach')
    if (options.pidFile) args.push('--pid-file', options.pidFile)
    if (options.noSubreaper) args.push('--no-subreaper')
    if (options.noPivot) args.push('--no-pivot')
    if (options.emptyNs) args.push('--empty-ns', options.emptyNs)
    if (options.autoDedup) args.push('--auto-dedup')
    if (options.lazyPages) args.push('--lazy-pages')

    await execa(this.command, [...this.globalOptions, 'restore', ...args, id])
  }

  async run(id: string, bundle: string, options: RunOptions = {}) {
    const args = ['--bundle', bundle]

    if (options.consoleSocket) args.push('--console-socket', options.consoleSocket)
    if (options.detach) args.push('--detach')
    if (options.pidFile) args.push('--pid-file', options.pidFile)
    if (options.noSubreaper) args.push('--no-subpreaper')
    if (options.noPivot) args.push('--no-pivot')
    if (options.noNewKeyring) args.push('--no-new-keyring')
    if (options.preserveFDs) args.push('--preserve-fds', options.preserveFDs.toString())

    await execa(this.command, [...this.globalOptions, 'run', ...args, id], {stdio: 'inherit'})
  }

  async start(id: string) {
    await execa(this.command, [...this.globalOptions, 'start', id])
  }

  async state(id: string): Promise<Container> {
    const res = await execa(this.command, [...this.globalOptions, 'state', id])
    return JSON.parse(res.stdout)
  }
}
