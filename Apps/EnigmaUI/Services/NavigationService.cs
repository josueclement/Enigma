using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using EnigmaUI.Model;
using EnigmaUI.Services.Interfaces;

namespace EnigmaUI.Services;

public class NavigationService : ObservableObject, INavigationService
{
    public object? CurrentViewModel
    {
        get => _currentViewModel;
        set => SetProperty(ref _currentViewModel, value);
    }
    private object? _currentViewModel;
    
    public ObservableCollection<NavigationItem> NavigationItems { get; set; } = [];
}