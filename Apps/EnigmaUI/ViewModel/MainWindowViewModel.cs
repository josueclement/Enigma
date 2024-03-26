using System;
using CommunityToolkit.Mvvm.ComponentModel;
using EnigmaUI.Model;
using EnigmaUI.Services.Interfaces;
using EnigmaUI.ViewModel.Pages;
using Microsoft.Extensions.DependencyInjection;

namespace EnigmaUI.ViewModel;

public class MainWindowViewModel : ObservableValidator
{
    #region Constructor
    
    public MainWindowViewModel(INavigationService navigationService,
        HomePageViewModel homePageViewModel,
        IServiceProvider services)
    {
        NavigationService = navigationService;
        NavigationService.CurrentViewModel = homePageViewModel;
        NavigationService.NavigationItems.Add(services.GetRequiredService<NavigationItem>());
        NavigationService.NavigationItems.Add(services.GetRequiredService<NavigationItem>());
        NavigationService.NavigationItems.Add(services.GetRequiredService<NavigationItem>());
        
    }
    
    #endregion
    
    #region Properties

    public INavigationService NavigationService { get; }

    #endregion
}