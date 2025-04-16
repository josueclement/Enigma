using System.Windows;
using System.Windows.Controls;

namespace Enigma.WpfApp.Views.Dialogs;

public partial class PasswordDialog : UserControl
{
    public PasswordDialog()
    {
        InitializeComponent();
        DataContext = this;
    }

    public static readonly DependencyProperty IsDataValidProperty =
        DependencyProperty.Register(name: nameof(IsDataValid),
                                    propertyType: typeof(bool),
                                    ownerType: typeof(PasswordDialog),
                                    typeMetadata: new PropertyMetadata(false));
    
    public bool IsDataValid
    {
        get => (bool)GetValue(IsDataValidProperty);
        set => SetValue(IsDataValidProperty, value);
    }

    private void KeyPassword_OnPasswordChanged(object sender, RoutedEventArgs e)
    {
        IsDataValid = KeyPassword.Password.Length > 0;
    }
}