#!/usr/bin/env node
// Scaffold only: no persistent private key, no Gateway connection and no remote tools.
const args = process.argv.slice(2);
const help = [
  'VPS Commander Device Agent (G7.2b prototype; NOT production-ready)',
  '',
  'Usage: vpsc-agent --help | --version | doctor',
  '',
  '  doctor   Check local Node and OS support without connecting anywhere.',
  '',
  'Pairing, device enrollment, outbound transport and remote command execution',
  'are NOT implemented or published by this scaffold.',
].join('\n');
if (args.length === 1 && (args[0] === '--help' || args[0] === '-h')) {
  process.stdout.write(help + '\n');
} else if (args.length === 1 && args[0] === '--version') {
  process.stdout.write('0.0.0-dev\n');
} else if (args.length === 1 && args[0] === 'doctor') {
  const supported = ['win32','linux','darwin'].includes(process.platform)
    && Number(process.versions.node.split('.')[0]) >= 20;
  process.stdout.write(JSON.stringify({prototype:true,remoteExecutionEnabled:false,
    platform:process.platform,node:process.versions.node,supported})+'\n');
  if (!supported) process.exitCode = 2;
} else {
  process.stderr.write('Unsupported or unavailable command. Agent transport is not enabled. Use --help.\n');
  process.exitCode = 2;
}
