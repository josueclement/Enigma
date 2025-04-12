using System.Windows.Controls;
using Microsoft.Extensions.Logging;

namespace Enigma.WpfApp.Controls;

public abstract class NavigationPageBase : Page
{
    private readonly ILogger<NavigationPageBase> _logger;

    protected NavigationPageBase(ILogger<NavigationPageBase> logger)
    {
        _logger = logger;
    }

    public virtual void OnAppeared()
    {
        _logger.LogTrace("OnAppeared: {type}", GetType().Name);
    }

    public virtual void OnDisappeared()
    {
        _logger.LogTrace("OnDisappeared: {type}", GetType().Name);
    }
}