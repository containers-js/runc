// See: https://github.com/opencontainers/runtime-spec/tree/v1.0.2

/** State holds information about the runtime state of the container. */
export interface State {
  /** Version is the version of the specification that is supported. */
  ociVersion: string
  /** ID is the container ID */
  id: string
  /** Status is the runtime status of the container. */
  status: string
  /** Pid is the process ID for the container process. */
  pid?: number
  /** Bundle is the path to the container's bundle directory. */
  bundle: string
  /** Annotations are key values associated with the container. */
  annotations?: Record<string, string>
}

/** Spec is the base configuration for the container. */
export interface Spec {
  /** Version of the Open Container Initiative Runtime Specification with which the bundle complies. */
  ociVersion: string
  /** Process configures the container process. */
  process?: Process
  /** Root configures the container's root filesystem. */
  root?: Root
  /** Hostname configures the container's hostname. */
  hostname?: string
  /** Mounts configures additional mounts (on top of Root). */
  mounts?: Mount[]
  /** Hooks configures callbacks for container lifecycle events. */
  hooks?: Hooks
  /** Annotations contains arbitrary metadata for the container. */
  annotations?: Record<string, string>
  /** Linux is platform-specific configuration for Linux based containers. */
  linux?: Linux
  /** Solaris is platform-specific configuration for Solaris based containers. */
  solaris?: Solaris
  /** Windows is platform-specific configuration for Windows based containers. */
  windows?: Windows
  /** VM specifies configuration for virtual-machine-based containers. */
  vm?: VM
}

/** Process contains information to start a specific application inside the container. */
export interface Process {
  /** Terminal creates an interactive terminal for the container. */
  terminal?: boolean
  /** ConsoleSize specifies the size of the console. */
  consoleSize?: Box
  /** User specifies user information for the process. */
  user: User
  /** Args specifies the binary and arguments for the application to execute. */
  args?: string[]
  /** CommandLine specifies the full command line for the application to execute on Windows. */
  commandLine?: string
  /** Env populates the process environment for the process. */
  env?: string[]
  /** Cwd is the current working directory for the process and must be relative to the container's root. */
  cwd: string
  /** Capabilities are Linux capabilities that are kept for the process. */
  capabilities?: LinuxCapabilities
  /** Rlimits specifies rlimit options to apply to the process. */
  rlimits?: POSIXRlimit[]
  /** NoNewPrivileges controls whether additional privileges could be gained by processes in the container. */
  noNewPrivileges?: boolean
  /** ApparmorProfile specifies the apparmor profile for the container. */
  apparmorProfile?: string
  /** Specify an oom_score_adj for the container. */
  oomScoreAdj?: number
  /** SelinuxLabel specifies the selinux context that the container process is run as. */
  selinuxLabel?: string
}

/**
 * LinuxCapabilities specifies the whitelist of capabilities that are kept for a process.
 *
 * @see http://man7.org/linux/man-pages/man7/capabilities.7.html
 */
export interface LinuxCapabilities {
  /** Bounding is the set of capabilities checked by the kernel. */
  bounding?: string[]
  /** Effective is the set of capabilities checked by the kernel. */
  effective?: string[]
  /** Inheritable is the capabilities preserved across execve. */
  inheritable?: string[]
  /** Permitted is the limiting superset for effective capabilities. */
  permitted?: string[]
  /** Ambient is the ambient set of capabilities that are kept. */
  ambient?: string[]
}

/** Box specifies dimensions of a rectangle. Used for specifying the size of a console. */
export interface Box {
  /** Height is the vertical dimension of a box. */
  height: number
  /** Width is the horizontal dimension of a box. */
  width: number
}

/** User specifies specific user (and group) information for the container process. */
export interface User {
  /** UID is the user id. */
  uid: number
  /** GID is the group id. */
  gid: number
  /** Umask is the umask for the init process. */
  umask?: number
  /** AdditionalGids are additional group ids set for the container's process. */
  additionalGids?: number[]
  /** Username is the user name. */
  username?: string
}

/** Root contains information about the container's root filesystem on the host. */
export interface Root {
  /** Path is the absolute path to the container's root filesystem. */
  path: string
  /** Readonly makes the root filesystem for the container readonly before the process is executed. */
  readonly?: boolean
}

/** Mount specifies a mount for a container. */
export interface Mount {
  /** Destination is the absolute path where the mount will be placed in the container. */
  destination: string
  /** Type specifies the mount kind. */
  type?: string
  /** Source specifies the source path of the mount. */
  source?: string
  /** Options are fstab style mount options. */
  options?: string[]
}

/** Hook specifies a command that is run at a particular event in the lifecycle of a container */
export interface Hook {
  path: string
  args?: string[]
  env?: string[]
  timeout?: number
}

// Hooks specifies a command that is run in the container at a particular event in the lifecycle of a container
// Hooks for container setup and teardown
export interface Hooks {
  // Prestart is Deprecated. Prestart is a list of hooks to be run before the container process is executed.
  // It is called in the Runtime Namespace
  prestart?: Hook[]
  // CreateRuntime is a list of hooks to be run after the container has been created but before pivot_root or any equivalent operation has been called
  // It is called in the Runtime Namespace
  createRuntime?: Hook[]
  // CreateContainer is a list of hooks to be run after the container has been created but before pivot_root or any equivalent operation has been called
  // It is called in the Container Namespace
  createContainer?: Hook[]
  // StartContainer is a list of hooks to be run after the start operation is called but before the container process is started
  // It is called in the Container Namespace
  startContainer?: Hook[]
  // Poststart is a list of hooks to be run after the container process is started.
  // It is called in the Runtime Namespace
  poststart?: Hook[]
  // Poststop is a list of hooks to be run after the container process exits.
  // It is called in the Runtime Namespace
  poststop?: Hook[]
}

// Linux contains platform-specific configuration for Linux based containers.
export interface Linux {
  // UIDMapping specifies user mappings for supporting user namespaces.
  uidMappings?: LinuxIDMapping[]
  // GIDMapping specifies group mappings for supporting user namespaces.
  gidMappings?: LinuxIDMapping[]
  // Sysctl are a set of key value pairs that are set for the container on start
  sysctl?: Record<string, string>
  // Resources contain cgroup information for handling resource constraints
  // for the container
  resources?: LinuxResources
  // CgroupsPath specifies the path to cgroups that are created and/or joined by the container.
  // The path is expected to be relative to the cgroups mountpoint.
  // If resources are specified, the cgroups at CgroupsPath will be updated based on resources.
  cgroupsPath?: string
  // Namespaces contains the namespaces that are created and/or joined by the container
  namespaces?: LinuxNamespace[]
  // Devices are a list of device nodes that are created for the container
  devices?: LinuxDevice[]
  // Seccomp specifies the seccomp security settings for the container.
  seccomp?: LinuxSeccomp
  // RootfsPropagation is the rootfs mount propagation mode for the container.
  rootfsPropagation?: string
  // MaskedPaths masks over the provided paths inside the container.
  maskedPaths?: string[]
  // ReadonlyPaths sets the provided paths as RO inside the container.
  readonlyPaths?: string[]
  // MountLabel specifies the selinux context for the mounts in the container.
  mountLabel?: string
  // IntelRdt contains Intel Resource Director Technology (RDT) information for
  // handling resource constraints (e.g., L3 cache, memory bandwidth) for the container
  intelRdt?: LinuxIntelRdt
  // Personality contains configuration for the Linux personality syscall
  personality?: LinuxPersonality
}

// LinuxNamespace is the configuration for a Linux namespace
export interface LinuxNamespace {
  // Type is the type of namespace
  type: LinuxNamespaceType
  // Path is a path to an existing namespace persisted on disk that can be joined
  // and is of the same type
  path?: string
}

// LinuxNamespaceType is one of the Linux namespaces
export enum LinuxNamespaceType {
  // PIDNamespace for isolating process IDs
  PIDNamespace = 'pid',
  // NetworkNamespace for isolating network devices, stacks, ports, etc
  NetworkNamespace = 'network',
  // MountNamespace for isolating mount points
  MountNamespace = 'mount',
  // IPCNamespace for isolating System V IPC, POSIX message queues
  IPCNamespace = 'ipc',
  // UTSNamespace for isolating hostname and NIS domain name
  UTSNamespace = 'uts',
  // UserNamespace for isolating user and group IDs
  UserNamespace = 'user',
  // CgroupNamespace for isolating cgroup hierarchies
  CgroupNamespace = 'cgroup',
}

// LinuxIDMapping specifies UID/GID mappings
export interface LinuxIDMapping {
  // ContainerID is the starting UID/GID in the container
  containerID: number
  // HostID is the starting UID/GID on the host to be mapped to 'ContainerID'
  hostID: number
  // Size is the number of IDs to be mapped
  size: number
}

/** POSIXRlimit type and restrictions */
export interface POSIXRlimit {
  /** Type of the rlimit to set */
  type: string
  /** Hard is the hard limit for the specified type */
  hard: number
  /** Soft is the soft limit for the specified type */
  soft: number
}

// LinuxHugepageLimit structure corresponds to limiting kernel hugepages
export interface LinuxHugepageLimit {
  // Pagesize is the hugepage size
  // Format: "<size><unit-prefix>B' (e.g. 64KB, 2MB, 1GB, etc.)
  pageSize: string
  // Limit is the limit of "hugepagesize" hugetlb usage
  limit: number
}

// LinuxInterfacePriority for network interfaces
export interface LinuxInterfacePriority {
  // Name is the name of the network interface
  name: string
  // Priority for the interface
  priority: number
}

// linuxBlockIODevice holds major:minor format supported in blkio cgroup
export interface linuxBlockIODevice {
  // Major is the device's major number.
  major: number
  // Minor is the device's minor number.
  minor: number
}

// LinuxWeightDevice struct holds a `major:minor weight` pair for weightDevice
export interface LinuxWeightDevice extends linuxBlockIODevice {
  // Weight is the bandwidth rate for the device.
  weight?: number
  // LeafWeight is the bandwidth rate for the device while competing with the cgroup's child cgroups, CFQ scheduler only
  leafWeight?: number
}

// LinuxThrottleDevice struct holds a `major:minor rate_per_second` pair
export interface LinuxThrottleDevice extends linuxBlockIODevice {
  // Rate is the IO rate limit per cgroup per device
  rate: number
}

// LinuxBlockIO for Linux cgroup 'blkio' resource management
export interface LinuxBlockIO {
  // Specifies per cgroup weight
  weight?: number
  // Specifies tasks' weight in the given cgroup while competing with the cgroup's child cgroups, CFQ scheduler only
  leafWeight?: number
  // Weight per cgroup per device, can override BlkioWeight
  weightDevice?: LinuxWeightDevice[]
  // IO read rate limit per cgroup per device, bytes per second
  throttleReadBpsDevice?: LinuxThrottleDevice[]
  // IO write rate limit per cgroup per device, bytes per second
  throttleWriteBpsDevice?: LinuxThrottleDevice[]
  // IO read rate limit per cgroup per device, IO per second
  throttleReadIOPSDevice?: LinuxThrottleDevice[]
  // IO write rate limit per cgroup per device, IO per second
  throttleWriteIOPSDevice?: LinuxThrottleDevice[]
}

// LinuxMemory for Linux cgroup 'memory' resource management
export interface LinuxMemory {
  // Memory limit (in bytes).
  limit?: number
  // Memory reservation or soft_limit (in bytes).
  reservation?: number
  // Total memory limit (memory + swap).
  swap?: number
  // Kernel memory limit (in bytes).
  kernel?: number
  // Kernel memory limit for tcp (in bytes)
  kernelTCP?: number
  // How aggressive the kernel will swap memory pages.
  swappiness?: number
  // DisableOOMKiller disables the OOM killer for out of memory conditions
  disableOOMKiller?: boolean
  // Enables hierarchical memory accounting
  useHierarchy?: boolean
}

// LinuxCPU for Linux cgroup 'cpu' resource management
export interface LinuxCPU {
  // CPU shares (relative weight (ratio) vs. other cgroups with cpu shares).
  shares?: number
  // CPU hardcap limit (in usecs). Allowed cpu time in a given period.
  quota?: number
  // CPU period to be used for hardcapping (in usecs).
  period?: number
  // How much time realtime scheduling may use (in usecs).
  realtimeRuntime?: number
  // CPU period to be used for realtime scheduling (in usecs).
  realtimePeriod?: number
  // CPUs to use within the cpuset. Default is to use any CPU available.
  cpus?: string
  // List of memory nodes in the cpuset. Default is to use any available memory node.
  mems?: string
}

// LinuxPids for Linux cgroup 'pids' resource management (Linux 4.3)
export interface LinuxPids {
  // Maximum number of PIDs. Default is "no limit".
  limit: number
}

// LinuxNetwork identification and priority configuration
export interface LinuxNetwork {
  // Set class identifier for container's network packets
  classID?: number
  // Set priority of network traffic for container
  priorities?: LinuxInterfacePriority[]
}

// LinuxRdma for Linux cgroup 'rdma' resource management (Linux 4.11)
export interface LinuxRdma {
  // Maximum number of HCA handles that can be opened. Default is "no limit".
  hcaHandles?: number
  // Maximum number of HCA objects that can be created. Default is "no limit".
  hcaObjects?: number
}

// LinuxResources has container runtime resource constraints
export interface LinuxResources {
  // Devices configures the device whitelist.
  devices?: LinuxDeviceCgroup[]
  // Memory restriction configuration
  memory?: LinuxMemory
  // CPU resource restriction configuration
  cpu?: LinuxCPU
  // Task resource restriction configuration.
  pids?: LinuxPids
  // BlockIO restriction configuration
  blockIO?: LinuxBlockIO
  // Hugetlb limit (in bytes)
  hugepageLimits?: LinuxHugepageLimit[]
  // Network restriction configuration
  network?: LinuxNetwork
  // Rdma resource restriction configuration.
  // Limits are a set of key value pairs that define RDMA resource limits,
  // where the key is device name and value is resource limits.
  rdma?: Record<string, LinuxRdma>
}

// LinuxDevice represents the mknod information for a Linux special device file
export interface LinuxDevice {
  // Path to the device.
  path: string
  // Device type, block, char, etc.
  type: string
  // Major is the device's major number.
  major: number
  // Minor is the device's minor number.
  minor: number
  // FileMode permission bits for the device.
  fileMode?: number
  // UID of the device.
  uid?: number
  // Gid of the device.
  gid?: number
}

// LinuxDeviceCgroup represents a device rule for the whitelist controller
export interface LinuxDeviceCgroup {
  // Allow or deny
  allow: boolean
  // Device type, block, char, etc.
  type?: string
  // Major is the device's major number.
  major?: number
  // Minor is the device's minor number.
  minor?: number
  // Cgroup access permissions format, rwm.
  access?: string
}

// LinuxPersonalityDomain refers to a personality domain.
export enum LinuxPersonalityDomain {
  // PerLinux is the standard Linux personality
  PerLinux = 'LINUX',
  // PerLinux32 sets personality to 32 bit
  PerLinux32 = 'LINUX32',
}

// LinuxPersonalityFlag refers to an additional personality flag. None are currently defined.
export enum LinuxPersonalityFlag {}

// LinuxPersonality represents the Linux personality syscall input
export interface LinuxPersonality {
  // Domain for the personality
  domain: LinuxPersonalityDomain
  // Additional flags
  flags?: LinuxPersonalityFlag[]
}

// Solaris contains platform-specific configuration for Solaris application containers.
export interface Solaris {
  // SMF FMRI which should go "online" before we start the container process.
  milestone?: string
  // Maximum set of privileges any process in this container can obtain.
  limitpriv?: string
  // The maximum amount of shared memory allowed for this container.
  maxShmMemory?: string
  // Specification for automatic creation of network resources for this container.
  anet?: SolarisAnet[]
  // Set limit on the amount of CPU time that can be used by container.
  cappedCPU?: SolarisCappedCPU
  // The physical and swap caps on the memory that can be used by this container.
  cappedMemory?: SolarisCappedMemory
}

// SolarisCappedCPU allows users to set limit on the amount of CPU time that can be used by container.
export interface SolarisCappedCPU {
  ncpus?: string
}

// SolarisCappedMemory allows users to set the physical and swap caps on the memory that can be used by this container.
export interface SolarisCappedMemory {
  physical?: string
  swap?: string
}

// SolarisAnet provides the specification for automatic creation of network resources for this container.
export interface SolarisAnet {
  // Specify a name for the automatically created VNIC datalink.
  linkname?: string
  // Specify the link over which the VNIC will be created.
  lowerLink?: string
  // The set of IP addresses that the container can use.
  allowedAddress?: string
  // Specifies whether allowedAddress limitation is to be applied to the VNIC.
  configureAllowedAddress?: string
  // The value of the optional default router.
  defrouter?: string
  // Enable one or more types of link protection.
  linkProtection?: string
  // Set the VNIC's macAddress
  macAddress?: string
}

// Windows defines the runtime configuration for Windows based containers, including Hyper-V containers.
export interface Windows {
  // LayerFolders contains a list of absolute paths to directories containing image layers.
  layerFolders: string[]
  // Devices are the list of devices to be mapped into the container.
  devices?: WindowsDevice[]
  // Resources contains information for handling resource constraints for the container.
  resources?: WindowsResources
  // CredentialSpec contains a JSON object describing a group Managed Service Account (gMSA) specification.
  credentialSpec?: object
  // Servicing indicates if the container is being started in a mode to apply a Windows Update servicing operation.
  servicing?: boolean
  // IgnoreFlushesDuringBoot indicates if the container is being started in a mode where disk writes are not flushed during its boot process.
  ignoreFlushesDuringBoot?: boolean
  // HyperV contains information for running a container with Hyper-V isolation.
  hyperv?: WindowsHyperV
  // Network restriction configuration.
  network?: WindowsNetwork
}

// WindowsDevice represents information about a host device to be mapped into the container.
export interface WindowsDevice {
  // Device identifier: interface class GUID, etc.
  id: string
  // Device identifier type: "class", etc.
  idType: string
}

// WindowsResources has container runtime resource constraints for containers running on Windows.
export interface WindowsResources {
  // Memory restriction configuration.
  memory?: WindowsMemoryResources
  // CPU resource restriction configuration.
  cpu?: WindowsCPUResources
  // Storage restriction configuration.
  storage?: WindowsStorageResources
}

// WindowsMemoryResources contains memory resource management settings.
export interface WindowsMemoryResources {
  // Memory limit in bytes.
  limit?: number
}

// WindowsCPUResources contains CPU resource management settings.
export interface WindowsCPUResources {
  // Number of CPUs available to the container.
  count?: number
  // CPU shares (relative weight to other containers with cpu shares).
  shares?: number
  // Specifies the portion of processor cycles that this container can use as a percentage times 100.
  maximum?: number
}

// WindowsStorageResources contains storage resource management settings.
export interface WindowsStorageResources {
  // Specifies maximum Iops for the system drive.
  iops?: number
  // Specifies maximum bytes per second for the system drive.
  bps?: number
  // Sandbox size specifies the minimum size of the system drive in bytes.
  sandboxSize?: number
}

// WindowsNetwork contains network settings for Windows containers.
export interface WindowsNetwork {
  // List of HNS endpoints that the container should connect to.
  endpointList?: string[]
  // Specifies if unqualified DNS name resolution is allowed.
  allowUnqualifiedDNSQuery?: boolean
  // Comma separated list of DNS suffixes to use for name resolution.
  DNSSearchList?: string[]
  // Name (ID) of the container that we will share with the network stack.
  networkSharedContainerName?: string
  // name (ID) of the network namespace that will be used for the container.
  networkNamespace?: string
}

// WindowsHyperV contains information for configuring a container to run with Hyper-V isolation.
export interface WindowsHyperV {
  // UtilityVMPath is an optional path to the image used for the Utility VM.
  utilityVMPath?: string
}

// VM contains information for virtual-machine-based containers.
export interface VM {
  // Hypervisor specifies hypervisor-related configuration for virtual-machine-based containers.
  hypervisor?: VMHypervisor
  // Kernel specifies kernel-related configuration for virtual-machine-based containers.
  kernel: VMKernel
  // Image specifies guest image related configuration for virtual-machine-based containers.
  image?: VMImage
}

// VMHypervisor contains information about the hypervisor to use for a virtual machine.
export interface VMHypervisor {
  // Path is the host path to the hypervisor used to manage the virtual machine.
  path: string
  // Parameters specifies parameters to pass to the hypervisor.
  parameters?: string[]
}

// VMKernel contains information about the kernel to use for a virtual machine.
export interface VMKernel {
  // Path is the host path to the kernel used to boot the virtual machine.
  path: string
  // Parameters specifies parameters to pass to the kernel.
  parameters?: string[]
  // InitRD is the host path to an initial ramdisk to be used by the kernel.
  initrd?: string
}

// VMImage contains information about the virtual machine root image.
export interface VMImage {
  // Path is the host path to the root image that the VM kernel would boot into.
  path: string
  // Format is the root image format type (e.g. "qcow2", "raw", "vhd", etc).
  format: string
}

// LinuxSeccomp represents syscall restrictions
export interface LinuxSeccomp {
  defaultAction: LinuxSeccompAction
  architectures?: Arch[]
  flags?: LinuxSeccompFlag[]
  syscalls?: LinuxSyscall[]
}

// Arch used for additional architectures
// Additional architectures permitted to be used for system calls
// By default only the native architecture of the kernel is permitted
export enum Arch {
  ArchX86 = 'SCMP_ARCH_X86',
  ArchX86_64 = 'SCMP_ARCH_X86_64',
  ArchX32 = 'SCMP_ARCH_X32',
  ArchARM = 'SCMP_ARCH_ARM',
  ArchAARCH64 = 'SCMP_ARCH_AARCH64',
  ArchMIPS = 'SCMP_ARCH_MIPS',
  ArchMIPS64 = 'SCMP_ARCH_MIPS64',
  ArchMIPS64N32 = 'SCMP_ARCH_MIPS64N32',
  ArchMIPSEL = 'SCMP_ARCH_MIPSEL',
  ArchMIPSEL64 = 'SCMP_ARCH_MIPSEL64',
  ArchMIPSEL64N32 = 'SCMP_ARCH_MIPSEL64N32',
  ArchPPC = 'SCMP_ARCH_PPC',
  ArchPPC64 = 'SCMP_ARCH_PPC64',
  ArchPPC64LE = 'SCMP_ARCH_PPC64LE',
  ArchS390 = 'SCMP_ARCH_S390',
  ArchS390X = 'SCMP_ARCH_S390X',
  ArchPARISC = 'SCMP_ARCH_PARISC',
  ArchPARISC64 = 'SCMP_ARCH_PARISC64',
}

// LinuxSeccompFlag is a flag to pass to seccomp(2).
export type LinuxSeccompFlag = string

// LinuxSeccompAction taken upon Seccomp rule match
export enum LinuxSeccompAction {
  ActKill = 'SCMP_ACT_KILL',
  ActTrap = 'SCMP_ACT_TRAP',
  ActErrno = 'SCMP_ACT_ERRNO',
  ActTrace = 'SCMP_ACT_TRACE',
  ActAllow = 'SCMP_ACT_ALLOW',
  ActLog = 'SCMP_ACT_LOG',
}

// LinuxSeccompOperator used to match syscall arguments in Seccomp
export enum LinuxSeccompOperator {
  OpNotEqual = 'SCMP_CMP_NE',
  OpLessThan = 'SCMP_CMP_LT',
  OpLessEqual = 'SCMP_CMP_LE',
  OpEqualTo = 'SCMP_CMP_EQ',
  OpGreaterEqual = 'SCMP_CMP_GE',
  OpGreaterThan = 'SCMP_CMP_GT',
  OpMaskedEqual = 'SCMP_CMP_MASKED_EQ',
}

// LinuxSeccompArg used for matching specific syscall arguments in Seccomp
export interface LinuxSeccompArg {
  index: number
  value: number
  valueTwo?: number
  op: LinuxSeccompOperator
}

// LinuxSyscall is used to match a syscall in Seccomp
export interface LinuxSyscall {
  names: string[]
  action: LinuxSeccompAction
  args?: LinuxSeccompArg[]
}

// LinuxIntelRdt has container runtime resource constraints for Intel RDT
// CAT and MBA features which introduced in Linux 4.10 and 4.12 kernel
export interface LinuxIntelRdt {
  // The identity for RDT Class of Service
  closID?: string
  // The schema for L3 cache id and capacity bitmask (CBM)
  // Format: "L3:<cache_id0>=<cbm0>;<cache_id1>=<cbm1>;..."
  l3CacheSchema?: string

  // The schema of memory bandwidth per L3 cache id
  // Format: "MB:<cache_id0>=bandwidth0;<cache_id1>=bandwidth1;..."
  // The unit of memory bandwidth is specified in "percentages" by
  // default, and in "MBps" if MBA Software Controller is enabled.
  memBwSchema?: string
}
