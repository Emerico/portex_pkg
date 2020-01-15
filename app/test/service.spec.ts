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

  afterAll(() => {
    oasis.disconnect();
  });
});