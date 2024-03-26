using CommunityToolkit.Mvvm.Input;

namespace EnigmaUI.Model;

public class NavigationItem
{
    public string? Title { get; set; }
    public RelayCommand? Command { get; set; }
    public string? IconResourceName { get; set; }
}