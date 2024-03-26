using System.Collections.ObjectModel;
using EnigmaUI.Model;

namespace EnigmaUI.Services.Interfaces;

public interface INavigationService
{
    object? CurrentViewModel { get; set; }
    ObservableCollection<NavigationItem> NavigationItems { get; set; }
}