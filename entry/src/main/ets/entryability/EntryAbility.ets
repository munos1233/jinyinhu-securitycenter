import { AbilityConstant, ConfigurationConstant, UIAbility, Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { window } from '@kit.ArkUI';
import { LiveStore } from '../model/LiveStore';
import { ScanTask } from '../model/ScanTask';
import { VERIFY_REJECT_CODE } from '../probe/ProbeTypes';
import { codeFromParameter, storeRejectCode } from '../probe/UpdateReject';
import bundleManager from '@ohos.bundle.bundleManager';
import util from '@ohos.util';
import fs from '@ohos.file.fs';
import { CenterError } from '../center/CenterError';
import { nowIso } from '../center/Clock';
import type { CacheClear, FileGrant, InstallerPort, TrustEntry } from '../center/CenterTypes';
import { HttpCloudTransport, ReputationClient, secureRandom } from '../cloud/ReputationClient';
import type { CloudConfig } from '../cloud/ReputationClient';
import { AppJudge } from '../engine/AppJudge';
import { RulePack } from '../engine/RulePack';
import type { RuleLoad } from '../engine/RulePack';
import { AppRunner } from '../feature/apps/AppRunner';
import type { AppSources } from '../feature/apps/AppRunner';
import { CleanRunner } from '../feature/clean/CleanRunner';
import type { CleanSources } from '../feature/clean/CleanRunner';
import { DuplicateFinder } from '../feature/clean/DuplicateFinder';
import { LargeFileFinder } from '../feature/clean/LargeFileFinder';
import { ExamRunner } from '../feature/exam/ExamRunner';
import type { ExamSources } from '../feature/exam/ExamRunner';
import { MalwareRunner } from '../feature/malware/MalwareRunner';
import type { MalwareSources } from '../feature/malware/MalwareRunner';
import { PermissionRunner } from '../feature/permission/PermissionRunner';
import { ProtectRunner } from '../feature/protect/ProtectRunner';
import { CenterStore } from '../record/CenterStore';
import { Disposition, FsOwnCache } from '../record/Disposition';
import type { DispositionPorts, OwnCache, QuarantineDoor } from '../record/Disposition';
import { PermissionActions } from '../record/PermissionActions';
import type { PermissionActionPorts } from '../record/PermissionActions';
import { HuksQuarantineCipher } from '../record/HuksQuarantineCipher';
import { Quarantine, FsByteStore } from '../record/Quarantine';
import { QuarantineBridge } from '../record/QuarantineBridge';
import type { QuarantineGrants, SessionRoots } from '../record/QuarantineBridge';
import { TrustList } from '../record/TrustList';
import { SandboxFiles } from '../record/Writer';
import { AccessPort, SdkAccessSource } from '../system/AccessPort';
import { GatedBundleCensus, SdkBundleSource } from '../system/BundleCensus';
import { CachePort, SdkCacheSource } from '../system/CachePort';
import { FileGrants, PreferencesGrantStore, SdkGrantPersist } from '../system/FileGrant';
import { FileOpen, FsFileView } from '../system/FileOpen';
import { GatedInstallerPort, sdkUninstallTool } from '../system/InstallerPort';
import { ParamPosturePort, SdkEl5Query, SdkParamReader } from '../system/PosturePort';
import { ProbedGate, SdkGateProbes } from '../system/SystemGate';
import { readCancel } from '../task/CancelFlag';
import { JobQueue } from '../task/JobQueue';
import { JobRunner, SystemClock } from '../task/JobRunner';
import { RunnerRegistry, RunnerSet } from '../task/RunnerRegistry';
import type { RuleDisplay } from '../pages/ProtectView';

const DOMAIN = 0x4A59;
const TAG = 'SecurityCenter';

export default class EntryAbility extends UIAbility {
  private rejectScan: boolean = false;
  private windowReady: boolean = false;
  private gate: ProbedGate | null = null;
  private generation: number = 0;

  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    let name = 'com.jinyinhu.securitycenter';
    if (typeof want.bundleName === 'string') {
      name = want.bundleName;
    }
    hilog.info(DOMAIN, TAG, 'onCreate %{public}s', name + '/' + launchParam.launchReason.toString());
    try {
      this.context.getApplicationContext().setColorMode(ConfigurationConstant.ColorMode.COLOR_MODE_LIGHT);
    } catch (err) {
      hilog.error(DOMAIN, TAG, 'colorMode %{public}s', JSON.stringify(err));
    }
    LiveStore.bind(this.context);
    LiveStore.prepare();
    this.prepareCenter();
    this.takeReject(want);
  }

  onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    hilog.info(DOMAIN, TAG, 'onNewWant %{public}s', launchParam.launchReason.toString());
    this.takeReject(want);
    this.scanIfRejected();
  }

  onDestroy(): void {
    hilog.info(DOMAIN, TAG, 'onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    LiveStore.restore().then(() => {
      this.open(windowStage);
    }).catch((err: Error) => {
      hilog.error(DOMAIN, TAG, 'restore %{public}s', JSON.stringify(err));
      this.open(windowStage);
    });
  }

  private open(windowStage: window.WindowStage): void {
    windowStage.loadContent('pages/Index', (err) => {
      if (err && err.code) {
        hilog.error(DOMAIN, TAG, 'load %{public}s', JSON.stringify(err));
        return;
      }
      hilog.info(DOMAIN, TAG, 'loaded');
      this.windowReady = true;
      this.scanIfRejected();
    });
    windowStage.getMainWindow().then((win: window.Window) => {
      win.setWindowBackgroundColor('#FFF7F6F2');
      win.setWindowSystemBarProperties({
        statusBarColor: '#FFF7F6F2',
        statusBarContentColor: '#E51C1E21',
        navigationBarColor: '#FFF7F6F2',
        navigationBarContentColor: '#E5000000'
      }).catch((err: Error) => {
        hilog.error(DOMAIN, TAG, 'systemBar %{public}s', JSON.stringify(err));
      });
    }).catch((err: Error) => {
      hilog.error(DOMAIN, TAG, 'window %{public}s', JSON.stringify(err));
    });
  }

  onWindowStageDestroy(): void {
    hilog.info(DOMAIN, TAG, 'onWindowStageDestroy');
  }

  private takeReject(want: Want): void {
    let value: Object | undefined = undefined;
    if (want.parameters !== undefined) {
      value = want.parameters['jinyinhuRejectCode'];
    }
    let code = codeFromParameter(value);
    if (code !== VERIFY_REJECT_CODE) {
      return;
    }
    if (!storeRejectCode(this.context.filesDir, code)) {
      hilog.error(DOMAIN, TAG, 'reject note failed');
      return;
    }
    this.rejectScan = true;
  }

  private scanIfRejected(): void {
    if (!this.rejectScan || !this.windowReady) {
      return;
    }
    this.rejectScan = false;
    ScanTask.run(this.context, []).catch((err: Object) => {
      hilog.error(DOMAIN, TAG, 'reject scan %{public}s', JSON.stringify(err));
    });
  }

  onForeground(): void {
    hilog.info(DOMAIN, TAG, 'onForeground');
    if (this.gate !== null) {
      this.gate.invalidate();
      this.generation++;
      AppStorage.setOrCreate<number>('center.gate.generation', this.generation);
    }
  }

  onBackground(): void {
    hilog.info(DOMAIN, TAG, 'onBackground');
  }

  private prepareCenter(): void {
    let context = this.context;
    let centerFiles = new SandboxFiles(context.filesDir);
    CenterStore.prepare(centerFiles, (): string | null => {
      try {
        let bytes = context.resourceManager.getRawFileContentSync('default_rules.json');
        return util.TextDecoder.create('utf-8').decodeWithStream(bytes);
      } catch (err) {
        return null;
      }
    });
    let gate = new ProbedGate(new SdkGateProbes(), (): number => Date.now());
    this.gate = gate;
    let census = new GatedBundleCensus(gate, new SdkBundleSource());
    let access = new AccessPort(gate, gate, new SdkAccessSource(), (): number => Date.now());
    let cache = new CachePort(gate, gate, new SdkCacheSource());
    let grants = new FileGrants(gate, gate, new PreferencesGrantStore(context), new SdkGrantPersist(), nowIso);
    let open = new FileOpen(new FsFileView());
    let posture = new ParamPosturePort(new SdkParamReader(), new SdkEl5Query());
    let key = '';
    try {
      key = util.TextDecoder.create('utf-8').decodeWithStream(
        context.resourceManager.getRawFileContentSync('rules/reputation_pub.pem'));
    } catch (err) { }
    let cloud = new ReputationClient(new LocalCloudConfig(key), new HttpCloudTransport(), readCancel);
    let judge = new AppJudge(cloud);
    let sources = new CenterSources(context.cacheDir, context.abilityInfo.bundleName);
    let exam = new ExamRunner(sources);
    let malware = new MalwareRunner(sources);
    let clean = new CleanRunner(sources);
    let duplicate = new DuplicateFinder();
    let large = new LargeFileFinder();
    let permission = new PermissionRunner();
    let apps = new AppRunner(sources);
    let protect = new ProtectRunner();
    let set = new RunnerSet();
    set.exam = (ctx, hand) => exam.run(ctx, hand);
    set.malware = (ctx, hand) => malware.run(ctx, hand);
    set.clean = (ctx, hand) => clean.run(ctx, hand);
    set.duplicate = (ctx, hand) => duplicate.run(ctx, hand);
    set.largeFile = (ctx, hand) => large.run(ctx, hand);
    set.permission = (ctx, hand) => permission.run(ctx, hand);
    set.apps = (ctx, hand) => apps.run(ctx, hand);
    set.protect = (ctx, hand) => protect.run(ctx, hand);
    let runner = new JobRunner({ posture: posture, census: census, cache: cache, files: grants, open: open,
      access: access, grants: access, judge: judge });
    let queue = new JobQueue(runner, gate, new SystemClock());
    let box = new Quarantine(centerFiles, new FsByteStore(context.filesDir), open, new HuksQuarantineCipher(),
      (): string => randomQuarantineId());
    let quarantine = new QuarantineBridge(box, new CenterQuarantineGrants(grants, open), gate,
      new QueueRoots(queue));
    let installer = new CheckedInstaller(gate);
    let dispositionPorts = new CenterDispositionPorts(installer, cache, new FsOwnCache(context.cacheDir), quarantine);
    let disposition = new Disposition(dispositionPorts);
    let permissionPorts = new CenterPermissionPorts(census, access, gate);
    let actions = new PermissionActions(permissionPorts);
    disposition.bindPermissions(actions);
    AppStorage.setOrCreate<ProbedGate>('center.gate', gate);
    AppStorage.setOrCreate<number>('center.gate.generation', 0);
    AppStorage.setOrCreate<FileGrants>('center.files', grants);
    AppStorage.setOrCreate<ReputationClient>('center.cloud', cloud);
    AppStorage.setOrCreate<Disposition>('center.disposition', disposition);
    AppStorage.setOrCreate<PermissionActions>('center.permission', actions);
    AppStorage.setOrCreate<QuarantineBridge>('center.quarantine', quarantine);
    AppStorage.setOrCreate<JobQueue>('center.queue', queue);
    let ruleDisplay: RuleDisplay = { cloudVersion: '', publicKeyPresent: key.trim().length > 0 };
    AppStorage.setOrCreate<RuleDisplay>('center.rules.display', ruleDisplay);
    gate.probe().catch((err: Error): void => {
      hilog.error(DOMAIN, TAG, 'center gate probe %{public}s', err.message);
    });
    RunnerRegistry.registerAll(set);
  }
}

class LocalCloudConfig implements CloudConfig {
  private key: string;
  constructor(key: string) { this.key = key; }
  endpoint(): string { return ''; }
  publicKey(): string { return this.key; }
}

class CenterSources implements ExamSources, MalwareSources, CleanSources, AppSources {
  private cacheDir: string;
  private name: string;
  constructor(cacheDir: string, name: string) { this.cacheDir = cacheDir; this.name = name; }
  trust(): TrustEntry[] { return TrustList.snapshot(); }
  ownCache(): Promise<number> { return cacheSize(this.cacheDir); }
  selfBundle(): string { return this.name; }
}

class CenterDispositionPorts implements DispositionPorts {
  installer: InstallerPort;
  cache: CacheClear;
  ownCache: OwnCache;
  quarantine: QuarantineDoor;
  constructor(installer: InstallerPort, cache: CacheClear, ownCache: OwnCache, quarantine: QuarantineDoor) {
    this.installer = installer; this.cache = cache; this.ownCache = ownCache; this.quarantine = quarantine;
  }
  rules(): RuleLoad { return RulePack.active(); }
}

class CenterQuarantineGrants implements QuarantineGrants {
  private grants: FileGrants;
  private open: FileOpen;
  constructor(grants: FileGrants, open: FileOpen) { this.grants = grants; this.open = open; }
  persisted(): FileGrant[] { return this.grants.persisted(); }
  async check(): Promise<void> { await this.grants.check(this.open); }
}

class QueueRoots implements SessionRoots {
  private queue: JobQueue;
  constructor(queue: JobQueue) { this.queue = queue; }
  roots(jobId: string): string[] {
    let request = this.queue.requestOf(jobId);
    return request !== null && request.scope === 'custom' ? request.uris.slice() : [];
  }
}

function randomQuarantineId(): string {
  let bytes = secureRandom(16);
  if (bytes.length !== 16) throw new Error('random unavailable');
  let out = '';
  for (let value of bytes) out += (value < 16 ? '0' : '') + value.toString(16);
  return out;
}

class CenterPermissionPorts implements PermissionActionPorts {
  census: GatedBundleCensus;
  access: AccessPort;
  gate: ProbedGate;
  constructor(census: GatedBundleCensus, access: AccessPort, gate: ProbedGate) {
    this.census = census; this.access = access; this.gate = gate;
  }
  async userGrant(name: string): Promise<boolean> {
    try { return bundleManager.getPermissionDefSync(name).grantMode === 1; } catch (err) { return false; }
  }
}

class CheckedInstaller implements InstallerPort {
  private gate: ProbedGate;
  private port: GatedInstallerPort = new GatedInstallerPort(sdkUninstallTool);
  constructor(gate: ProbedGate) { this.gate = gate; }
  async uninstall(bundleName: string): Promise<void> {
    if (this.gate.uninstall().status !== 'ready') throw new CenterError('unsupported', 'uninstall');
    await this.port.uninstall(bundleName);
  }
}

async function cacheSize(dir: string): Promise<number> {
  let total = 0;
  for (let name of fs.listFileSync(dir, { recursion: true })) {
    let stat = fs.lstatSync(dir + '/' + name);
    if (stat.isFile()) total += stat.size;
  }
  return total;
}
