const title = document.getElementById('stateTitle');
const message = document.getElementById('message');
const list = document.getElementById('missing');
const result = document.getElementById('result');
const retry = document.getElementById('retry');

async function refresh() {
  const status = await window.nodexDesktop.getBootstrapStatus();
  title.textContent = status.state === 'ready' ? 'NODEX готов' : 'Требуется подготовка';
  message.textContent = status.message || '';
  list.replaceChildren();
  for (const item of status.missing || []) {
    const li = document.createElement('li');
    li.textContent = `${item.label}: ${item.path}`;
    list.append(li);
  }
}
retry.addEventListener('click', async () => {
  retry.disabled = true; result.textContent = 'Повторная проверка…';
  try {
    const response = await window.nodexDesktop.retryBootstrap();
    result.textContent = response.ok ? 'Службы запущены.' : response.message;
    await refresh();
  } catch (error) { result.textContent = error.message; }
  finally { retry.disabled = false; }
});
document.getElementById('dataFolder').addEventListener('click', () => window.nodexDesktop.openDataFolder());
refresh().catch((error) => { message.textContent = error.message; });
