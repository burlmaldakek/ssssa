// FairPlayed — FairPlay decryption research tool.
// Runs mremap_encrypted experiments from a regular sandboxed (sideloaded) app.
#import <UIKit/UIKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include "fpcore.h"
#include "zipio.h"

#pragma mark - logging

static NSFileHandle *gLogFile;
static void (^gUILog)(NSString *);

static void FPLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void FPLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    printf("%s\n", s.UTF8String); fflush(stdout);
    @synchronized ([NSFileHandle class]) {
        [gLogFile writeData:[[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    }
    if (gUILog) gUILog(s);
}

static void core_log(void *ctx, const char *msg) { FPLog(@"%s", msg); }

static NSString *DocsDir(void) { return NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject; }
static NSString *WorkDir(void) {
    return [NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject stringByAppendingPathComponent:@"fpwork"];
}

#pragma mark - runner

@interface FPRunner : NSObject
+ (void)runEnvironment;
+ (void)probeInstalledAppsMatching:(NSString *)filter export:(BOOL)export;
+ (NSString *)processIPA:(NSString *)ipaPath;
+ (void)processAllDocumentsIPAs;
+ (void)embeddedExperiment;
+ (void)embeddedExport;
+ (void)copyTree:(NSString *)src to:(NSString *)dst skipped:(NSMutableArray *)skipped;
@end

@implementation FPRunner

+ (NSArray<NSString *> *)machOsUnder:(NSString *)root {
    NSMutableArray *out = [NSMutableArray array];
    NSDirectoryEnumerator *en = [[NSFileManager defaultManager] enumeratorAtPath:root];
    for (NSString *rel in en) {
        NSString *p = [root stringByAppendingPathComponent:rel];
        NSDictionary *a = en.fileAttributes;
        if (![a.fileType isEqualToString:NSFileTypeRegular] || a.fileSize < 4096) continue;
        if (fp_is_macho(p.fileSystemRepresentation)) [out addObject:rel];
    }
    return out;
}

+ (void)logEnvironment {
    struct utsname u; uname(&u);
    FPLog(@"== FairPlayed %@ | %s | iOS %@ | pid %d | uid %d",
          NSBundle.mainBundle.infoDictionary[@"CFBundleShortVersionString"], u.machine,
          UIDevice.currentDevice.systemVersion, getpid(), getuid());
    FPLog(@"bundle: %@", NSBundle.mainBundle.bundlePath);
    FPLog(@"docs:   %@", DocsDir());
    for (NSString *d in @[@"/private/var/containers/Bundle/Application", @"/var/containers/Bundle/Application",
                          NSBundle.mainBundle.bundlePath.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent]) {
        DIR *dir = opendir(d.fileSystemRepresentation);
        if (!dir) { FPLog(@"opendir(%@): %s", d, strerror(errno)); continue; }
        int n = 0; struct dirent *de; while ((de = readdir(dir))) n++;
        closedir(dir);
        FPLog(@"opendir(%@): OK, %d entries", d, n);
    }
}

// --- Installed apps (via LaunchServices private SPI) -------------------------------------------

+ (NSArray<NSDictionary *> *)installedApps {
    NSMutableArray *res = [NSMutableArray array];
    Class ws = NSClassFromString(@"LSApplicationWorkspace");
    id w = [ws respondsToSelector:@selector(defaultWorkspace)] ? [ws performSelector:@selector(defaultWorkspace)] : nil;
    NSArray *proxies = nil;
    for (NSString *sel in @[@"allInstalledApplications", @"allApplications"]) {
        if ([w respondsToSelector:NSSelectorFromString(sel)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            proxies = [w performSelector:NSSelectorFromString(sel)];
#pragma clang diagnostic pop
            FPLog(@"LSApplicationWorkspace.%@ -> %lu proxies", sel, (unsigned long)proxies.count);
            if (proxies.count) break;
        }
    }
    for (id p in proxies) {
        @try {
            NSString *bid = [p valueForKey:@"bundleIdentifier"];
            NSURL *url = [p valueForKey:@"bundleURL"];
            NSString *exe = [p valueForKey:@"bundleExecutable"];
            NSString *type = [p valueForKey:@"applicationType"];
            if (bid && url && exe) [res addObject:@{@"id": bid, @"path": url.path, @"exe": exe, @"type": type ?: @"?"}];
        } @catch (NSException *e) {}
    }
    // Enumeration is denied to unentitled apps on iOS 27; resolve explicitly named bundle IDs instead.
    NSString *targets = NSProcessInfo.processInfo.environment[@"FPD_TARGETS"];
    for (NSString *bid in [targets componentsSeparatedByString:@","]) {
        if (!bid.length) continue;
        NSDictionary *d = [self resolveBundleID:bid];
        if (d) [res addObject:d];
    }
    // Explicit installed .app paths (e.g. from `devicectl device install app` output).
    NSString *paths = NSProcessInfo.processInfo.environment[@"FPD_PATHS"];
    for (NSString *raw in [paths componentsSeparatedByString:@","]) {
        NSString *p = [raw stringByStandardizingPath];
        if (!p.length) continue;
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[p stringByAppendingPathComponent:@"Info.plist"]];
        NSString *exe = info[@"CFBundleExecutable"] ?: p.lastPathComponent.stringByDeletingPathExtension;
        NSError *lsErr = nil;
        NSArray *ls = [NSFileManager.defaultManager contentsOfDirectoryAtPath:[p stringByAppendingPathComponent:@"SC_Info"] error:&lsErr];
        FPLog(@"FPD_PATHS %@: Info.plist readable=%d exe=%@ SC_Info=%@", p, info != nil, exe,
              ls ? [ls componentsJoinedByString:@","] : lsErr.localizedDescription);
        [res addObject:@{@"id": info[@"CFBundleIdentifier"] ?: p.lastPathComponent, @"path": p, @"exe": exe, @"type": @"Target"}];
    }
    return res;
}

+ (NSDictionary *)resolveBundleID:(NSString *)bid {
    NSString *path = nil, *exe = nil, *type = nil;
    Class proxyCls = NSClassFromString(@"LSApplicationProxy");
    if ([proxyCls respondsToSelector:@selector(applicationProxyForIdentifier:)]) {
        @try {
            id p = [proxyCls performSelector:@selector(applicationProxyForIdentifier:) withObject:bid];
            path = [[p valueForKey:@"bundleURL"] path];
            exe = [p valueForKey:@"bundleExecutable"];
            type = [p valueForKey:@"applicationType"];
            FPLog(@"LSApplicationProxy(%@): url=%@ exe=%@ type=%@ installed=%@", bid, path, exe, type,
                  [p respondsToSelector:NSSelectorFromString(@"isInstalled")] ? [p valueForKey:@"isInstalled"] : @"?");
        } @catch (NSException *e) { FPLog(@"LSApplicationProxy(%@): %@", bid, e.reason); }
    }
    Class recCls = NSClassFromString(@"LSApplicationRecord");
    SEL initSel = NSSelectorFromString(@"initWithBundleIdentifier:allowPlaceholder:error:");
    if (recCls && [recCls instancesRespondToSelector:initSel]) {
        @try {
            NSError *err = nil;
            // init consumes self and returns +1; spell that out so ARC does not over-release when it returns nil.
            typedef id (*LSRecInitFn)(__attribute__((ns_consumed)) id, SEL, NSString *, BOOL, NSError * __autoreleasing *)
                __attribute__((ns_returns_retained));
            LSRecInitFn initFn = (LSRecInitFn)[recCls instanceMethodForSelector:initSel];
            id r = initFn([recCls alloc], initSel, bid, NO, &err);
            NSURL *u = r ? [r valueForKey:@"URL"] : nil;
            NSURL *x = nil;
            @try { x = r ? [r valueForKey:@"executableURL"] : nil; } @catch (NSException *e) {}
            FPLog(@"LSApplicationRecord(%@): url=%@ exe=%@ err=%@", bid, u.path, x.path, err.localizedDescription);
            if (!path && u) path = u.path;
            if (!exe && x) exe = x.lastPathComponent;
        } @catch (NSException *e) { FPLog(@"LSApplicationRecord(%@): %@", bid, e.reason); }
    }
    if (path && !exe) {
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"Info.plist"]];
        exe = info[@"CFBundleExecutable"];
        FPLog(@"  Info.plist readable=%d", info != nil);
    }
    if (!path || !exe) return nil;
    return @{@"id": bid, @"path": path, @"exe": exe, @"type": @"Target"};
}

+ (void)probeInstalledAppsMatching:(NSString *)filter export:(BOOL)export {
    FPLog(@"=== installed-app probe (filter=%@) ===", filter ?: @"<user apps>");
    NSMutableArray *apps = [[self installedApps] mutableCopy];
    if (filter.length) {
        // iOS 27 denies broad installed-app enumeration to unentitled apps, but
        // the upstream research also tries resolving a specifically named bundle ID.
        NSDictionary *resolved = [self resolveBundleID:filter];
        if (resolved) {
            BOOL duplicate = NO;
            for (NSDictionary *existing in apps) {
                if ([existing[@"id"] isEqualToString:resolved[@"id"]]) { duplicate = YES; break; }
            }
            if (!duplicate) [apps addObject:resolved];
        } else {
            FPLog(@"exact bundle-ID resolution returned no app for %@", filter);
        }
    }
    int readable = 0, encrypted = 0, decrypted = 0;
    for (NSDictionary *a in apps) {
        BOOL wanted = [a[@"type"] isEqualToString:@"Target"] ||
                      (filter.length ? [a[@"id"] containsString:filter] : [a[@"type"] isEqualToString:@"User"]);
        if (!wanted) continue;
        if ([a[@"id"] isEqualToString:NSBundle.mainBundle.bundleIdentifier]) continue;
        NSString *exe = [a[@"path"] stringByAppendingPathComponent:a[@"exe"]];
        int fd = open(exe.fileSystemRepresentation, O_RDONLY);
        int e = errno;
        FPLog(@"[%@] %@ type=%@ open=%s", a[@"id"], exe, a[@"type"], fd >= 0 ? "OK" : strerror(e));
        if (fd < 0) continue;
        close(fd); readable++;
        fp_slice_t sl[FP_MAX_SLICES]; int n = 0; char err[256];
        if (fp_parse(exe.fileSystemRepresentation, sl, FP_MAX_SLICES, &n, err, sizeof err) != 0 || n == 0) { FPLog(@"  parse: %s", err); continue; }
        if (!(sl[0].has_enc && sl[0].cryptid)) { FPLog(@"  not encrypted (cryptid=%u)", sl[0].cryptid); continue; }
        encrypted++;
        int modes[] = { FP_MODE_R_CID2, FP_MODE_RX_CID1, FP_MODE_R_CID1 };
        int ok = fp_probe_file(exe.fileSystemRepresentation, modes, 3, core_log, NULL);
        if (ok > 0) {
            decrypted++;
            if (export) [self exportInstalledApp:a];
        }
    }
    FPLog(@"=== installed-app probe done: %lu apps listed, %d readable, %d encrypted, %d decrypted ===",
          (unsigned long)apps.count, readable, encrypted, decrypted);
}

+ (void)exportInstalledApp:(NSDictionary *)a {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *work = [WorkDir() stringByAppendingPathComponent:a[@"id"]];
    [fm removeItemAtPath:work error:nil];
    NSString *appName = [a[@"path"] lastPathComponent];
    NSString *dst = [[work stringByAppendingPathComponent:@"Payload"] stringByAppendingPathComponent:appName];
    [fm createDirectoryAtPath:dst.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:nil];
    NSError *err;
    if (![fm copyItemAtPath:a[@"path"] toPath:dst error:&err]) { FPLog(@"  copy bundle failed: %@", err); return; }
    int fails = 0;
    for (NSString *rel in [self machOsUnder:dst]) {
        NSString *src = [a[@"path"] stringByAppendingPathComponent:rel];
        NSString *out = [dst stringByAppendingPathComponent:rel];
        int r = fp_decrypt_file(src.fileSystemRepresentation, out.fileSystemRepresentation, core_log, NULL);
        FPLog(@"  %@: %s", rel, r == 0 ? "decrypted" : r == 1 ? "not encrypted" : "FAILED");
        if (r < 0) fails++;
    }
    NSString *ipa = [[DocsDir() stringByAppendingPathComponent:@"Decrypted"] stringByAppendingPathComponent:
                     [NSString stringWithFormat:@"%@%@.ipa", a[@"id"], fails ? @"-PARTIAL" : @"-decrypted"]];
    [fm createDirectoryAtPath:ipa.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:nil];
    char zerr[512] = {0};
    if (zip_create_from_dir(work.fileSystemRepresentation, ipa.fileSystemRepresentation, zerr, sizeof zerr) == 0)
        FPLog(@"  wrote %@", ipa);
    else
        FPLog(@"  zip failed: %s", zerr);
}

// --- IPA files ----------------------------------------------------------------------------------

+ (void)pathVariantExperiment:(NSString *)exe appDir:(NSString *)appDir {
    // Does decryption depend on where the binary lives / on SC_Info being next to it?
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *base = [WorkDir() stringByAppendingPathComponent:@"variants"];
    [fm removeItemAtPath:base error:nil];
    NSString *exeName = exe.lastPathComponent;
    NSString *lone = [[base stringByAppendingPathComponent:@"lone"] stringByAppendingPathComponent:exeName];
    NSString *tmpApp = [NSTemporaryDirectory() stringByAppendingPathComponent:@"fpvariant/X.app"];
    [fm removeItemAtPath:tmpApp.stringByDeletingLastPathComponent error:nil];
    [fm createDirectoryAtPath:lone.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:tmpApp withIntermediateDirectories:YES attributes:nil error:nil];
    [fm copyItemAtPath:exe toPath:lone error:nil];
    [fm copyItemAtPath:exe toPath:[tmpApp stringByAppendingPathComponent:exeName] error:nil];
    NSString *sc = [appDir stringByAppendingPathComponent:@"SC_Info"];
    if ([fm fileExistsAtPath:sc]) [fm copyItemAtPath:sc toPath:[tmpApp stringByAppendingPathComponent:@"SC_Info"] error:nil];
    // C: X.app without SC_Info; D: plain (non-.app) directory with SC_Info; E: SC_Info with .sinf only.
    NSString *appNoSC = [base stringByAppendingPathComponent:@"C/Y.app"];
    NSString *plainSC = [base stringByAppendingPathComponent:@"D/plain"];
    NSString *sinfOnly = [base stringByAppendingPathComponent:@"E/Z.app"];
    for (NSString *d in @[appNoSC, plainSC, sinfOnly]) {
        [fm createDirectoryAtPath:d withIntermediateDirectories:YES attributes:nil error:nil];
        [fm copyItemAtPath:exe toPath:[d stringByAppendingPathComponent:exeName] error:nil];
    }
    if ([fm fileExistsAtPath:sc]) {
        [fm copyItemAtPath:sc toPath:[plainSC stringByAppendingPathComponent:@"SC_Info"] error:nil];
        NSString *e = [sinfOnly stringByAppendingPathComponent:@"SC_Info"];
        [fm createDirectoryAtPath:e withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *sinf = [exeName stringByAppendingPathExtension:@"sinf"];
        [fm copyItemAtPath:[sc stringByAppendingPathComponent:sinf] toPath:[e stringByAppendingPathComponent:sinf] error:nil];
    }
    int modes[] = { FP_MODE_R_CID2 };
    NSArray *variants = @[
        @[@"A: binary alone, no SC_Info", lone],
        @[@"B: tmp/X.app + full SC_Info", [tmpApp stringByAppendingPathComponent:exeName]],
        @[@"C: Y.app without SC_Info", [appNoSC stringByAppendingPathComponent:exeName]],
        @[@"D: plain dir (no .app) + full SC_Info", [plainSC stringByAppendingPathComponent:exeName]],
        @[@"E: Z.app + SC_Info with .sinf only", [sinfOnly stringByAppendingPathComponent:exeName]],
    ];
    for (NSArray *v in variants) {
        FPLog(@"-- variant %@: %@", v[0], v[1]);
        fp_probe_file([v[1] fileSystemRepresentation], modes, 1, core_log, NULL);
    }
}

+ (NSString *)processIPA:(NSString *)ipaPath {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *name = ipaPath.lastPathComponent.stringByDeletingPathExtension;
    FPLog(@"=== IPA: %@ (%.1f MB) ===", ipaPath.lastPathComponent,
          [[fm attributesOfItemAtPath:ipaPath error:nil] fileSize] / 1048576.0);
    NSString *work = [WorkDir() stringByAppendingPathComponent:name];
    [fm removeItemAtPath:work error:nil];
    [fm createDirectoryAtPath:work withIntermediateDirectories:YES attributes:nil error:nil];
    char err[512] = {0};
    if (zip_extract_all(ipaPath.fileSystemRepresentation, work.fileSystemRepresentation, err, sizeof err) != 0) {
        FPLog(@"extract failed: %s", err); return nil;
    }
    NSString *payload = [work stringByAppendingPathComponent:@"Payload"];
    NSString *app = nil;
    for (NSString *f in [fm contentsOfDirectoryAtPath:payload error:nil]) if ([f.pathExtension isEqualToString:@"app"]) app = f;
    if (!app) { FPLog(@"no Payload/*.app"); return nil; }
    NSString *appDir = [payload stringByAppendingPathComponent:app];
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[appDir stringByAppendingPathComponent:@"Info.plist"]];
    NSString *mainExe = [appDir stringByAppendingPathComponent:info[@"CFBundleExecutable"] ?: app.stringByDeletingPathExtension];
    FPLog(@"app: %@ id=%@ ver=%@ SC_Info=%@", app, info[@"CFBundleIdentifier"], info[@"CFBundleShortVersionString"],
          [fm contentsOfDirectoryAtPath:[appDir stringByAppendingPathComponent:@"SC_Info"] error:nil]);

    FPLog(@"-- main executable, all modes, in extracted bundle:");
    int modes[] = { FP_MODE_R_CID2, FP_MODE_RX_CID1, FP_MODE_R_CID1 };
    int ok = fp_probe_file(mainExe.fileSystemRepresentation, modes, 3, core_log, NULL);
    BOOL variantsRequested = NSProcessInfo.processInfo.environment[@"FPD_VARIANTS"] != nil;
    if (variantsRequested) [self pathVariantExperiment:mainExe appDir:appDir];
    if (ok <= 0) {
        if (!variantsRequested) {
            FPLog(@"=== direct import attempt failed; running SC_Info/path variants for diagnostics ===");
            [self pathVariantExperiment:mainExe appDir:appDir];
        }
        FPLog(@"=== main executable NOT decrypted; no IPA will be exported ===");
        FPLog(@"Hint: upstream requires the target app inside the installed helper bundle; an IPA imported into Documents is in the data container.");
        return nil;
    }

    int fails = 0, done = 0;
    for (NSString *rel in [self machOsUnder:appDir]) {
        NSString *p = [appDir stringByAppendingPathComponent:rel];
        NSString *tmp = [p stringByAppendingString:@".fpdec"];
        int r = fp_decrypt_file(p.fileSystemRepresentation, tmp.fileSystemRepresentation, core_log, NULL);
        if (r == 0) { rename(tmp.fileSystemRepresentation, p.fileSystemRepresentation); done++; }
        else unlink(tmp.fileSystemRepresentation);
        if (r < 0) fails++;
        FPLog(@"  %@: %s", rel, r == 0 ? "decrypted" : r == 1 ? "not encrypted" : "FAILED");
    }
    NSString *outDir = [DocsDir() stringByAppendingPathComponent:@"Decrypted"];
    [fm createDirectoryAtPath:outDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *ipa = [outDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@%@.ipa", name, fails ? @"-PARTIAL" : @"-decrypted"]];
    if (zip_create_from_dir(work.fileSystemRepresentation, ipa.fileSystemRepresentation, err, sizeof err) != 0) {
        FPLog(@"zip failed: %s", err); return nil;
    }
    [fm removeItemAtPath:work error:nil];
    FPLog(@"=== wrote %@ (%d binaries decrypted, %d failed) ===", ipa.lastPathComponent, done, fails);
    return ipa;
}

// fairplayd reads <dir of binary>/SC_Info/<exe>.sinf, and System Policy denies it access to app data
// containers. Test locations fairplayd can read: our own (installed) bundle, reached directly or via symlinks.
+ (NSString *)embeddedRoot {
    return [NSBundle.mainBundle.resourcePath stringByAppendingPathComponent:@"EmbeddedPayload"];
}

+ (void)embeddedExperiment {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *root = [self embeddedRoot];
    NSArray *names = [fm contentsOfDirectoryAtPath:root error:nil];
    FPLog(@"=== embedded-payload experiment: %@ (%lu entries) ===", root, (unsigned long)names.count);
    int modes3[] = { FP_MODE_R_CID2, FP_MODE_RX_CID1, FP_MODE_R_CID1 };
    int modes1[] = { FP_MODE_R_CID2 };
    NSString *outDir = [DocsDir() stringByAppendingPathComponent:@"Decrypted"];
    [fm createDirectoryAtPath:outDir withIntermediateDirectories:YES attributes:nil error:nil];
    for (NSString *name in names) {
        NSString *dir = [root stringByAppendingPathComponent:name];
        NSDictionary *pinfo = [NSDictionary dictionaryWithContentsOfFile:[dir stringByAppendingPathComponent:@"Info.plist"]];
        NSString *exeName = pinfo[@"CFBundleExecutable"] ?: name;
        NSString *exe = [dir stringByAppendingPathComponent:exeName];
        NSString *sc = [dir stringByAppendingPathComponent:@"SC_Info"];
        BOOL haveExe = [fm fileExistsAtPath:exe], haveSC = [fm fileExistsAtPath:sc];
        FPLog(@"[%@] exe=%d SC_Info=%@", name, haveExe, [[fm contentsOfDirectoryAtPath:sc error:nil] componentsJoinedByString:@","]);
        if (!haveExe) continue;
        NSMutableArray *decryptedFrom = [NSMutableArray array];

        FPLog(@"-- J: binary + SC_Info inside own app bundle: %@", exe);
        if (fp_probe_file(exe.fileSystemRepresentation, modes3, 3, core_log, NULL) > 0) [decryptedFrom addObject:exe];

        NSString *base = [WorkDir() stringByAppendingPathComponent:[@"embedded-" stringByAppendingString:name]];
        [fm removeItemAtPath:base error:nil];
        NSMutableArray *variants = [NSMutableArray array];
        if (haveSC) {
            NSString *h = [base stringByAppendingPathComponent:@"H"];
            [fm createDirectoryAtPath:h withIntermediateDirectories:YES attributes:nil error:nil];
            [fm copyItemAtPath:exe toPath:[h stringByAppendingPathComponent:exeName] error:nil];
            symlink(sc.fileSystemRepresentation, [h stringByAppendingPathComponent:@"SC_Info"].fileSystemRepresentation);
            [variants addObject:@[@"H: container binary, SC_Info -> symlink to bundle SC_Info", h]];

            NSString *i = [base stringByAppendingPathComponent:@"I"];
            NSString *isc = [i stringByAppendingPathComponent:@"SC_Info"];
            [fm createDirectoryAtPath:isc withIntermediateDirectories:YES attributes:nil error:nil];
            [fm copyItemAtPath:exe toPath:[i stringByAppendingPathComponent:exeName] error:nil];
            for (NSString *f in [fm contentsOfDirectoryAtPath:sc error:nil])
                symlink([sc stringByAppendingPathComponent:f].fileSystemRepresentation, [isc stringByAppendingPathComponent:f].fileSystemRepresentation);
            [variants addObject:@[@"I: container binary, SC_Info/* -> per-file symlinks into bundle", i]];
        }
        NSString *ext = NSProcessInfo.processInfo.environment[@"FPD_SCLINK"];
        if (ext.length) {
            NSString *f = [base stringByAppendingPathComponent:@"F"];
            [fm createDirectoryAtPath:f withIntermediateDirectories:YES attributes:nil error:nil];
            [fm copyItemAtPath:exe toPath:[f stringByAppendingPathComponent:exeName] error:nil];
            symlink(ext.fileSystemRepresentation, [f stringByAppendingPathComponent:@"SC_Info"].fileSystemRepresentation);
            [variants addObject:@[[@"F: container binary, SC_Info -> symlink to " stringByAppendingString:ext], f]];
        }
        for (NSArray *v in variants) {
            NSString *bin = [v[1] stringByAppendingPathComponent:exeName];
            FPLog(@"-- %@: %@", v[0], bin);
            if (fp_probe_file(bin.fileSystemRepresentation, modes1, 1, core_log, NULL) > 0) [decryptedFrom addObject:bin];
        }
        if (decryptedFrom.count) {
            NSString *out = [outDir stringByAppendingPathComponent:[exeName stringByAppendingString:@".decrypted"]];
            int r = fp_decrypt_file([decryptedFrom.firstObject fileSystemRepresentation], out.fileSystemRepresentation, core_log, NULL);
            FPLog(@"=== %@: decrypted via %lu variant(s); wrote %@ (rc=%d) ===", name, (unsigned long)decryptedFrom.count, out, r);
        } else {
            FPLog(@"=== %@: no variant decrypted ===", name);
        }
    }
}

+ (void)copyTree:(NSString *)src to:(NSString *)dst skipped:(NSMutableArray *)skipped {
    NSFileManager *fm = NSFileManager.defaultManager;
    [fm createDirectoryAtPath:dst withIntermediateDirectories:YES attributes:nil error:nil];
    NSDirectoryEnumerator *en = [fm enumeratorAtPath:src];
    for (NSString *rel in en) {
        NSString *type = en.fileAttributes.fileType;
        NSString *s = [src stringByAppendingPathComponent:rel], *d = [dst stringByAppendingPathComponent:rel];
        if ([rel.lastPathComponent isEqualToString:@"SC_Info"]) { [en skipDescendants]; [skipped addObject:rel]; continue; }
        if ([type isEqualToString:NSFileTypeDirectory]) {
            [fm createDirectoryAtPath:d withIntermediateDirectories:YES attributes:nil error:nil];
        } else if ([type isEqualToString:NSFileTypeSymbolicLink]) {
            NSString *t = [fm destinationOfSymbolicLinkAtPath:s error:nil];
            if (!t || ![fm createSymbolicLinkAtPath:d withDestinationPath:t error:nil]) [skipped addObject:rel];
        } else if (![fm copyItemAtPath:s toPath:d error:nil]) {
            [skipped addObject:rel];
        }
    }
}

// Full export: EmbeddedPayload/<name>/ holds a complete copy of <name>.app (placed there by embed_ipa.sh).
// Every encrypted Mach-O is decrypted from its in-bundle path (where fairplayd can read it and its SC_Info),
// written into a container copy of the app, and the result is zipped into Documents/Decrypted/<name>-decrypted.ipa.
+ (void)embeddedExport {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *root = [self embeddedRoot];
    for (NSString *name in [fm contentsOfDirectoryAtPath:root error:nil]) @autoreleasepool {
        NSString *src = [root stringByAppendingPathComponent:name];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[src stringByAppendingPathComponent:@"Info.plist"]];
        if (!info) { FPLog(@"[%@] no Info.plist; not a full app copy, skipping export", name); continue; }
        FPLog(@"=== export %@ (%@ %@) ===", name, info[@"CFBundleIdentifier"], info[@"CFBundleShortVersionString"]);
        NSString *work = [WorkDir() stringByAppendingPathComponent:[@"export-" stringByAppendingString:name]];
        NSString *appDst = [[work stringByAppendingPathComponent:@"Payload"] stringByAppendingPathComponent:[name stringByAppendingPathExtension:@"app"]];
        [fm removeItemAtPath:work error:nil];
        // The app sandbox denies reading SC_Info contents even inside our own bundle (only fairplayd needs them),
        // and a decrypted IPA does not need them either: copy everything else, tolerating unreadable files.
        NSMutableArray *skipped = [NSMutableArray array];
        [self copyTree:src to:appDst skipped:skipped];
        FPLog(@"copied bundle; skipped %lu item(s): %@", (unsigned long)skipped.count, [skipped componentsJoinedByString:@", "]);
        int dec = 0, plain = 0, fail = 0;
        NSMutableArray *failed = [NSMutableArray array];
        for (NSString *rel in [self machOsUnder:src]) @autoreleasepool {
            int r = fp_decrypt_file([src stringByAppendingPathComponent:rel].fileSystemRepresentation,
                                    [appDst stringByAppendingPathComponent:rel].fileSystemRepresentation, core_log, NULL);
            if (r == 0) dec++; else if (r == 1) plain++; else { fail++; [failed addObject:rel]; }
            FPLog(@"  %@ %@", r == 0 ? @"[DECRYPTED]" : r == 1 ? @"[plain]    " : @"[FAILED]   ", rel);
        }
        NSString *outDir = [DocsDir() stringByAppendingPathComponent:@"Decrypted"];
        [fm createDirectoryAtPath:outDir withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *ipa = [outDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@%@.ipa", name, fail ? @"-PARTIAL" : @"-decrypted"]];
        [fm removeItemAtPath:ipa error:nil];
        char zerr[512] = {0};
        int zr = zip_create_from_dir(work.fileSystemRepresentation, ipa.fileSystemRepresentation, zerr, sizeof zerr);
        [fm removeItemAtPath:work error:nil];
        FPLog(@"=== %@: %d decrypted, %d not encrypted, %d failed%@; %@ ===", name, dec, plain, fail,
              fail ? [NSString stringWithFormat:@" (%@)", [failed componentsJoinedByString:@", "]] : @"",
              zr == 0 ? [@"wrote " stringByAppendingString:ipa.lastPathComponent] : [NSString stringWithFormat:@"zip failed: %s", zerr]);
    }
}

+ (void)processAllDocumentsIPAs {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSMutableArray *ipas = [NSMutableArray array];
    for (NSString *dir in @[DocsDir(), [DocsDir() stringByAppendingPathComponent:@"Inbox"]])
        for (NSString *f in [fm contentsOfDirectoryAtPath:dir error:nil])
            if ([f.pathExtension.lowercaseString isEqualToString:@"ipa"]) [ipas addObject:[dir stringByAppendingPathComponent:f]];
    if (!ipas.count) FPLog(@"no .ipa files in Documents/");
    for (NSString *p in ipas) @autoreleasepool { [self processIPA:p]; }
}

+ (void)runEnvironment {
    NSDictionary *env = NSProcessInfo.processInfo.environment;
    NSString *mode = env[@"FPD_AUTORUN"];
    if (!mode) return;
    [self logEnvironment];
    if ([mode isEqualToString:@"installed"] || [mode isEqualToString:@"all"])
        [self probeInstalledAppsMatching:env[@"FPD_FILTER"] export:env[@"FPD_EXPORT"] != nil];
    if ([mode isEqualToString:@"embedded"] || [mode isEqualToString:@"all"])
        [self embeddedExperiment];
    if ([mode isEqualToString:@"export"])
        [self embeddedExport];
    if ([mode isEqualToString:@"ipa"] || [mode isEqualToString:@"all"])
        [self processAllDocumentsIPAs];
    FPLog(@"== autorun finished ==");
    if (env[@"FPD_EXIT"]) exit(0);
}

@end

#pragma mark - UI

@interface FPViewController : UIViewController <UIDocumentPickerDelegate>
@property (nonatomic, strong) UITextView *textView;
@property (nonatomic, strong) UIActivityIndicatorView *activity;
@end

@implementation FPViewController

- (UIButton *)buttonWithTitle:(NSString *)title tag:(NSInteger)tag {
    UIButton *b = [UIButton buttonWithConfiguration:UIButtonConfiguration.tintedButtonConfiguration primaryAction:nil];
    b.configuration.cornerStyle = UIButtonConfigurationCornerStyleMedium;
    b.configuration.title = title;
    b.tag = tag;
    [b addTarget:self action:@selector(tap:) forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;

    UILabel *title = [UILabel new];
    title.text = @"FairPlayed Lab";
    title.font = [UIFont systemFontOfSize:27 weight:UIFontWeightBold];

    UILabel *subtitle = [UILabel new];
    subtitle.text = @"On-device experiments • native C • no JIT";
    subtitle.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
    subtitle.textColor = UIColor.secondaryLabelColor;
    subtitle.numberOfLines = 0;

    UILabel *warning = [UILabel new];
    warning.text = @"Experimental: imported IPAs may fail because fairplayd cannot read app data containers. The installed-app probe tests a separate route.";
    warning.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
    warning.textColor = UIColor.secondaryLabelColor;
    warning.numberOfLines = 0;

    UIStackView *buttons = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self buttonWithTitle:@"Import IPA and test" tag:0],
        [self buttonWithTitle:@"Test installed apps" tag:1],
        [self buttonWithTitle:@"Share logs / decrypted IPAs" tag:2]
    ]];
    buttons.axis = UILayoutConstraintAxisVertical;
    buttons.distribution = UIStackViewDistributionFillEqually;
    buttons.spacing = 8;

    self.activity = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    self.activity.hidesWhenStopped = YES;

    self.textView = [[UITextView alloc] init];
    self.textView.editable = NO;
    self.textView.scrollEnabled = YES;
    self.textView.backgroundColor = UIColor.secondarySystemBackgroundColor;
    self.textView.layer.cornerRadius = 12;
    self.textView.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    self.textView.text = @"Ready.\nImport an encrypted IPA to test the direct data-container path, or test an app already installed from the App Store.\n";

    UIStackView *header = [[UIStackView alloc] initWithArrangedSubviews:@[title, subtitle, warning, buttons, self.activity]];
    header.axis = UILayoutConstraintAxisVertical;
    header.spacing = 8;

    UIStackView *root = [[UIStackView alloc] initWithArrangedSubviews:@[header, self.textView]];
    root.axis = UILayoutConstraintAxisVertical;
    root.spacing = 10;
    root.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:root];
    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [root.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:12],
        [root.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-12],
        [root.topAnchor constraintEqualToAnchor:g.topAnchor constant:10],
        [root.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-10],
        [header.heightAnchor constraintGreaterThanOrEqualToConstant:180],
    ]];

    __weak typeof(self) ws = self;
    gUILog = ^(NSString *s) {
        dispatch_async(dispatch_get_main_queue(), ^{
            FPViewController *self = ws;
            if (!self) return;
            UITextView *tv = self.textView;
            tv.text = [tv.text stringByAppendingFormat:@"%@\n", s];
            [tv scrollRangeToVisible:NSMakeRange(tv.text.length, 0)];
        });
    };
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{ [FPRunner runEnvironment]; });
}

- (void)tap:(UIButton *)b {
    switch (b.tag) {
        case 0: {
            UTType *ipa = [UTType typeWithIdentifier:@"com.apple.itunes.ipa"];
            NSArray *types = ipa ? @[ipa, UTTypeZIP, UTTypeData] : @[UTTypeZIP, UTTypeData];
            UIDocumentPickerViewController *p = [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:types asCopy:YES];
            p.delegate = self;
            [self presentViewController:p animated:YES completion:nil];
            break;
        }
        case 1: {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Installed-app probe"
                message:@"Enter an exact bundle ID. On stock iOS 27, broad app enumeration may be denied. Leave empty to try that enumeration anyway. If a licensed app is readable and decrypts, the app will be exported."
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
                field.placeholder = @"com.example.app (exact bundle ID)";
                field.autocapitalizationType = UITextAutocapitalizationTypeNone;
                field.autocorrectionType = UITextAutocorrectionTypeNo;
            }];
            [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
            [alert addAction:[UIAlertAction actionWithTitle:@"Probe" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                NSString *filter = alert.textFields.firstObject.text;
                if (!filter.length) filter = nil;
                [self background:^{
                    FPLog(@"=== installed-app path probe requested (filter=%@) ===", filter ?: @"all user apps");
                    [FPRunner probeInstalledAppsMatching:filter export:YES];
                }];
            }]];
            [self presentViewController:alert animated:YES completion:nil];
            break;
        }
        case 2: {
            NSString *dir = [DocsDir() stringByAppendingPathComponent:@"Decrypted"];
            NSMutableArray *items = [NSMutableArray array];
            for (NSString *f in [NSFileManager.defaultManager contentsOfDirectoryAtPath:dir error:nil])
                [items addObject:[NSURL fileURLWithPath:[dir stringByAppendingPathComponent:f]]];
            NSURL *log = [NSURL fileURLWithPath:[DocsDir() stringByAppendingPathComponent:@"fairplayed.log"]];
            if ([[NSFileManager defaultManager] fileExistsAtPath:log.path]) [items addObject:log];
            if (!items.count) {
                [self appendStatus:@"Nothing to share yet. Run a test first."];
                break;
            }
            UIActivityViewController *av = [[UIActivityViewController alloc] initWithActivityItems:items applicationActivities:nil];
            av.popoverPresentationController.sourceView = b;
            av.popoverPresentationController.sourceRect = b.bounds;
            [self presentViewController:av animated:YES completion:nil];
            break;
        }
    }
}

- (void)appendStatus:(NSString *)s {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.textView.text = [self.textView.text stringByAppendingFormat:@"%@\n", s];
        [self.textView scrollRangeToVisible:NSMakeRange(self.textView.text.length, 0)];
    });
}

- (void)background:(dispatch_block_t)blk {
    [self.activity startAnimating];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [FPRunner logEnvironment];
        blk();
        dispatch_async(dispatch_get_main_queue(), ^{ [self.activity stopAnimating]; });
    });
}

- (void)documentPicker:(UIDocumentPickerViewController *)c didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *u = urls.firstObject;
    if (!u) return;
    NSString *dst = [DocsDir() stringByAppendingPathComponent:u.lastPathComponent];
    [NSFileManager.defaultManager removeItemAtPath:dst error:nil];
    NSError *copyError = nil;
    BOOL copied = [NSFileManager.defaultManager copyItemAtURL:u toURL:[NSURL fileURLWithPath:dst] error:&copyError];
    if (!copied) {
        [self appendStatus:[NSString stringWithFormat:@"Import failed: %@", copyError.localizedDescription ?: @"unknown error"]];
        return;
    }
    [self appendStatus:[NSString stringWithFormat:@"Imported %@", u.lastPathComponent]];
    [self background:^{
        NSString *result = [FPRunner processIPA:dst];
        if (result.length) FPLog(@"Export ready: %@", result);
        else FPLog(@"No decrypted IPA produced for %@", u.lastPathComponent);
    }];
}

@end

@interface SceneDelegate : UIResponder <UIWindowSceneDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation SceneDelegate
- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session options:(UISceneConnectionOptions *)opts {
    self.window = [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)scene];
    self.window.rootViewController = [FPViewController new];
    [self.window makeKeyAndVisible];
}
@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    NSString *logPath = [DocsDir() stringByAppendingPathComponent:@"fairplayed.log"];
    if (![NSFileManager.defaultManager fileExistsAtPath:logPath]) [NSData.data writeToFile:logPath atomically:NO];
    gLogFile = [NSFileHandle fileHandleForWritingAtPath:logPath];
    [gLogFile seekToEndOfFile];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(AppDelegate.class));
    }
}
