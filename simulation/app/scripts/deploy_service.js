const chalk = require('chalk');
const oasis = require('@oasislabs/client');

oasis.workspace.PortexPkg.deploy({
  header: {confidential: false},
})
.then(res => {
  console.log(`    ${chalk.green('Deployed')} PortexPkg at 0x${res.address.hex}`);
})
.catch(err => {
  console.error(
   `${chalk.red('error')}: could not deploy PortexPkg: ${err.message}`,
  );
})
.finally(() => {
  oasis.disconnect();
});
