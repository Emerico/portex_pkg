import oasis from '@oasislabs/client';

jest.setTimeout(20000);

describe('PortexPkg Test', () => {
  let service;

  beforeAll(async () => {
    service = await oasis.workspace.PortexPkg.deploy({
      header: {confidential: false},
      gasLimit: '0xe79732',
    });
  });

  it('deployed', async () => {
    expect(service).toBeTruthy();
  });
  
  it('master key simulation (16)', async () => {
    let mkey = await service.simpk16();
  });
  
  it('master key simulation (32)', async () => {
    let mkey = await service.simpk32();
  });
  
  it('master key simulation (64)', async () => {
    let mkey = await service.simpk64();
  });
  
  it('master key simulation (128)', async () => {
    let mkey = await service.simpk128();
  });
  
  it('master key simulation (256)', async () => {
    let mkey = await service.simpk256();
  });
  
  it('user key simulation', async () => {
    let mkey = await service.simuk('test');
  });
  
  afterAll(() => {
    oasis.disconnect();
  });
});