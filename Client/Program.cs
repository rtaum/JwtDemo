using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);

// Optional: in-process HybridCache; Duende v4 uses it to coalesce token fetches
builder.Services.AddDistributedMemoryCache();

// Duende token management (client-credentials)
builder.Services
    .AddClientCredentialsTokenManagement(options =>
    {
        // API token lifetime is 20s in the demo — refresh a bit early
        options.CacheLifetimeBuffer = 5; // seconds
    })
    .AddClient("oauth", client =>
    {
        client.TokenEndpoint = "http://localhost:5000/connect/token";
        client.ClientId      = "client-app";
        client.ClientSecret  = "client-secret";
        client.Scope         = "api.read";
    });

// HttpClient that auto-attaches & refreshes the Bearer token
builder.Services.AddClientCredentialsHttpClient("api", "oauth",
    http => http.BaseAddress = new Uri("http://localhost:5000"));

using var host = builder.Build();

var api = host.Services.GetRequiredService<IHttpClientFactory>().CreateClient("api");

// Config: N threads & optional timed run via env vars
int n = int.TryParse(Environment.GetEnvironmentVariable("LOAD_THREADS"), out var t) ? t : 50;
int minDelayMs = 10, maxDelayMs = 200;

var cts = new CancellationTokenSource();

// Optional: stop automatically after N seconds if DURATION_SEC is set
if (int.TryParse(Environment.GetEnvironmentVariable("DURATION_SEC"), out var duration) && duration > 0)
{
    _ = Task.Run(async () => { await Task.Delay(TimeSpan.FromSeconds(duration)); cts.Cancel(); });
}

// Ctrl+C to stop
Console.CancelKeyPress += (s, e) => { e.Cancel = true; cts.Cancel(); };

long total = 0, ok = 0, nonOk = 0, errors = 0;

// 1s stats reporter
var monitor = Task.Run(async () =>
{
    long lastTotal = 0;
    while (!cts.IsCancellationRequested)
    {
        try { await Task.Delay(1000, cts.Token); } catch { break; }
        var current = Interlocked.Read(ref total);
        var delta = current - lastTotal;
        lastTotal = current;
        Console.WriteLine($"[Client] req/s={delta}, total={current}, 200={Interlocked.Read(ref ok)}, non-200={Interlocked.Read(ref nonOk)}, errors={Interlocked.Read(ref errors)}");
    }
}, cts.Token);

// Launch N workers
var workers = Enumerable.Range(0, n).Select(_ => Task.Run(async () =>
{
    var rnd = new Random(Random.Shared.Next());
    while (!cts.IsCancellationRequested)
    {
        try
        {
            using var res = await api.GetAsync("/weather", cts.Token);
            Interlocked.Increment(ref total);
            if (res.IsSuccessStatusCode) Interlocked.Increment(ref ok);
            else Interlocked.Increment(ref nonOk);
        }
        catch (OperationCanceledException) { break; }
        catch
        {
            Interlocked.Increment(ref errors);
        }

        try
        {
            await Task.Delay(rnd.Next(minDelayMs, maxDelayMs + 1), cts.Token);
        }
        catch (OperationCanceledException) { break; }
    }
}, cts.Token)).ToArray();

Console.WriteLine($"[Client] Running {n} workers with {minDelayMs}-{maxDelayMs} ms jitter. Press Ctrl+C to stop.");
await Task.WhenAll(workers.Concat(new[] { monitor }));
