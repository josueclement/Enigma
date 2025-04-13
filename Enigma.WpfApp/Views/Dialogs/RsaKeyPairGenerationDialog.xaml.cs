using System.Windows.Controls;
using Wpf.Ui.Controls;

namespace Enigma.WpfApp.Views.Dialogs;

public partial class RsaKeyPairGenerationDialog : ContentDialog
{
    public RsaKeyPairGenerationDialog(ContentPresenter? contentPresenter)
        : base(contentPresenter)
    {
        InitializeComponent();
    }

    protected override void OnButtonClick(ContentDialogButton button)
    {
        base.OnButtonClick(button);
    }
}