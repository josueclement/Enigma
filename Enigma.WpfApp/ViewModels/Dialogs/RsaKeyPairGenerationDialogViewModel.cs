using System;
using CommunityToolkit.Mvvm.ComponentModel;

namespace Enigma.WpfApp.ViewModels.Dialogs;

public class RsaKeyPairGenerationDialogViewModel : ObservableObject
{
    private int _keySize;
    public int KeySize
    {
        get => _keySize;
        set => SetProperty(ref _keySize, value);
    }

    private string _password = String.Empty;
    public string Password
    {
        get => _password;
        set => SetProperty(ref _password, value);
    }
}