using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;

namespace Enigma.WpfApp.Views.Dialogs;

public partial class RsaKeyPairGenerationDialog : INotifyPropertyChanged
{
    public RsaKeyPairGenerationDialog()
    {
        InitializeComponent();
        DataContext = this;
    }

    public static readonly DependencyProperty IsDataValidProperty =
        DependencyProperty.Register(name: nameof(IsDataValid),
                                    propertyType: typeof(bool),
                                    ownerType: typeof(RsaKeyPairGenerationDialog),
                                    typeMetadata: new PropertyMetadata(true));
    
    public bool IsDataValid
    {
        get => (bool)GetValue(IsDataValidProperty);
        set => SetValue(IsDataValidProperty, value);
    }

    private int _keySize = 4096;
    public int KeySize
    {
        get => _keySize;
        set
        {
            if (SetField(ref _keySize, value))
                ValidateData();
        }
    }    

    private void ValidateData()
    {
        IsDataValid = _keySize % 1024 == 0;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }
}