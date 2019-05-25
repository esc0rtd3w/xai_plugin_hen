static const char * stage2cexbak = "/dev_rebug/rebug/cobra/stage2.cex.bak";
static const char * stage2dexbak = "/dev_rebug/rebug/cobra/stage2.dex.bak";
static const char * stage2cex = "/dev_rebug/rebug/cobra/stage2.cex";
static const char * stage2dex = "/dev_rebug/rebug/cobra/stage2.dex";

static const char * vshnrm = "/dev_rebug/vsh/module/vsh.self.nrm";
static const char * vshself= "/dev_rebug/vsh/module/vsh.self";
static const char * vshswp ="/dev_rebug/vsh/module/vsh.self.swp";

static const char * vshdsp = "/dev_rebug/vsh/module/vsh.self.dexsp";
static const char * vshcsp = "/dev_rebug/vsh/module/vsh.self.cexsp";

static const char * idxdat = "/dev_rebug/vsh/etc/index.dat";
static const char * idxswp = "/dev_rebug/vsh/etc/index.dat.swp";
static const char * idxnrm = "/dev_rebug/vsh/etc/index.dat.nrm";

static const char * vertxt = "/dev_rebug/vsh/etc/version.txt";
static const char * verswp = "/dev_rebug/vsh/etc/version.txt.swp";
static const char * vernrm = "/dev_rebug/vsh/etc/version.txt.nrm";

static const char * sysconfprx = "/dev_rebug/vsh/module/sysconf_plugin.sprx";
static const char * sysconfcex = "/dev_rebug/vsh/module/sysconf_plugin.sprx.cex";
static const char * sysconfdex = "/dev_rebug/vsh/module/sysconf_plugin.sprx.dex";

void toggle_cobra_enable();
void toggle_cobra_disable();
int cobra_mode();
int rebug_mode();
void debugsettings_mode();

void download_toolbox();
void install_toolbox();